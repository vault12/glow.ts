import { box, BoxKeyPair, randomBytes, secretbox, hash } from 'tweetnacl';
import { sha256 } from 'js-sha256';

import { Utils } from '../utils/utils';
import { NaClDriver, EncryptedMessage } from './nacl-driver.interface';
import { Keypair } from './keypair.interface';


/**
 * Implementation based on TweetNaCl.js: {@link https://github.com/dchest/tweetnacl-js}.
 * SHA256 is taken separately from `js-sha256` library, because TweetNacl only offers
 * SHA512 as hashing function, which is incompatible with the current Zax version.
 * {@link https://github.com/emn178/js-sha256}
 *
 * All the methods of this class are actually synchronous, but they are defined
 * as async to conform to the NaClDriver interface, which may have other implementations.
 */
export class JsNaClDriver implements NaClDriver {
  crypto_secretbox_KEYBYTES = secretbox.keyLength;

  async crypto_secretbox_random_nonce(): Promise<Uint8Array> {
    return randomBytes(secretbox.nonceLength);
  }

  async crypto_secretbox(message: Uint8Array, nonce: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
    return secretbox(message, nonce, key);
  }

  async crypto_secretbox_open(box: Uint8Array, nonce: Uint8Array, key: Uint8Array): Promise<Uint8Array | null> {
    return secretbox.open(box, nonce, key);
  }

  crypto_box_NONCEBYTES = box.nonceLength;

  async crypto_box(message: Uint8Array, nonce: Uint8Array, pk: Uint8Array, sk: Uint8Array): Promise<Uint8Array> {
    return box(message, nonce, pk, sk);
  }

  async crypto_box_open(
    cipher: Uint8Array, nonce: Uint8Array, pk: Uint8Array, sk: Uint8Array): Promise<Uint8Array | null> {
    return box.open(cipher, nonce, pk, sk);
  }

  async crypto_box_random_nonce(): Promise<Uint8Array> {
    return randomBytes(box.nonceLength);
  }

  async crypto_box_keypair(): Promise<Keypair> {
    const pair: BoxKeyPair = box.keyPair();
    return {
      boxPk: pair.publicKey,
      boxSk: pair.secretKey
    };
  }

  async crypto_box_keypair_from_raw_sk(key: Uint8Array): Promise<Keypair> {
    const pair: BoxKeyPair = box.keyPair.fromSecretKey(key);
    return {
      boxPk: pair.publicKey,
      boxSk: pair.secretKey
    };
  }

  async crypto_box_keypair_from_seed(seed: Uint8Array): Promise<Keypair> {
    // using SHA512 to hash, per original NaCl docs
    return this.crypto_box_keypair_from_raw_sk(hash(seed).subarray(0, box.secretKeyLength));
  }

  async crypto_hash_sha256(data: Uint8Array): Promise<Uint8Array> {
    return this.from_hex(sha256(data));
  }

  async random_bytes(size: number): Promise<Uint8Array> {
    return randomBytes(size);
  }

  // Helper methods are based on `js-nacl` implementations
  // https://github.com/tonyg/js-nacl/blob/cc70775cfc9d68a04905ca65c7f179b33a18066e/nacl_cooked.js

  async encode_latin1(data: string): Promise<Uint8Array> {
    const result = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i++) {
      const c = data.charCodeAt(i);
      if ((c & 0xff) !== c) throw { message: 'Cannot encode string in Latin1', str: data };
      result[i] = (c & 0xff);
    }
    return result;
  }

  async decode_latin1(data: Uint8Array): Promise<string> {
    const encoded = [];
    for (let i = 0; i < data.length; i++) {
      encoded.push(String.fromCharCode(data[i]));
    }
    return encoded.join('');
  }

  async encode_utf8(data: string): Promise<Uint8Array> {
    return this.encode_latin1(unescape(encodeURIComponent(data)));
  }

  async decode_utf8(data: Uint8Array): Promise<string> {
    return decodeURIComponent(escape(await this.decode_latin1(data)));
  }

  async to_hex(data: Uint8Array): Promise<string> {
    const encoded = [];
    for (let i = 0; i < data.length; i++) {
      const hexAlphabet = '0123456789abcdef';
      encoded.push(hexAlphabet[(data[i] >> 4) & 15]);
      encoded.push(hexAlphabet[data[i] & 15]);
    }
    return encoded.join('');
  }

  async from_hex(data: string): Promise<Uint8Array> {
    const result = new Uint8Array(data.length / 2);
    for (let i = 0; i < data.length / 2; i++) {
      result[i] = parseInt(data.substr(2 * i, 2), 16);
    }
    return result;
  }

  /**
   * h2(m) = sha256(sha256(64x0 + m))
   * Zero out initial sha256 block, and double hash 0-padded message
   * http://cs.nyu.edu/~dodis/ps/h-of-h.pdf
   */
  async h2(data: string | Uint8Array): Promise<Uint8Array> {
    if (!(data instanceof Uint8Array)) {
      data = await this.encode_latin1(data);
    }

    const extendedSource = new Uint8Array(64 + data.length);
    extendedSource.fill(0);
    extendedSource.set(data, 64);
    return this.crypto_hash_sha256(await this.crypto_hash_sha256(extendedSource));
  }

  // ---------- Encoding wrappers ----------

  /**
   * Encodes a binary message with `cryptobox`
   */
  async rawEncodeMessage(message: Uint8Array, pkTo: Uint8Array,
    skFrom: Uint8Array, nonceData?: number): Promise<EncryptedMessage> {
    const nonce = await this.makeNonce(nonceData);
    const ctext = await this.crypto_box(message, nonce, pkTo, skFrom);
    return {
      nonce: Utils.toBase64(nonce),
      ctext: Utils.toBase64(ctext)
    };
  }

  /**
   * Decodes a binary message with `cryptobox_open`
   */
  /* eslint-disable @typescript-eslint/explicit-module-boundary-types, @typescript-eslint/no-explicit-any */
  async rawDecodeMessage(nonce: Uint8Array, ctext: Uint8Array, pkFrom: Uint8Array, skTo: Uint8Array): Promise<any> {
    const data = await this.crypto_box_open(ctext, nonce, pkFrom, skTo);
    if (data) {
      const utf8 = await this.decode_utf8(data);
      return JSON.parse(utf8);
    }

    return data;
  }

  // ---------- Nonce helper ----------

  /**
   * Makes a timestamp nonce that a relay expects for any crypto operations.
   * Timestamp is the first 8 bytes, the rest is random, unless custom `data`
   * is specified. `data` will be packed as next 4 bytes after timestamp.
   */
  async makeNonce(data?: number): Promise<Uint8Array> {
    const nonce = await this.crypto_box_random_nonce();
    let headerLen;
    if (nonce.length !== this.crypto_box_NONCEBYTES) {
      throw new Error('[Mailbox] Wrong crypto_box nonce length');
    }
    // split timestamp integer as an array of bytes
    headerLen = 8; // max timestamp size
    const aTime = this.itoa(Math.floor(Date.now() / 1000));

    if (data) {
      headerLen += 4; // extra 4 bytes for custom data
    }

    // zero out nonce header area
    nonce.fill(0, 0, headerLen);
    // copy the timestamp into the first 8 bytes of nonce
    nonce.set(aTime, 8 - aTime.length);
    // copy data if present
    if (data) {
      const aData = this.itoa(data);
      nonce.set(aData, 12 - aData.length);
    }
    return nonce;
  }

  /**
   * Splits an integer into an array of bytes
   */
  private itoa(num: number): Uint8Array {
    // calculate length first
    let hex = num.toString(16);
    hex = hex.length & 1 ? `0${hex}` : hex;
    const len = hex.length / 2;
    const byteArray = new Uint8Array(len);

    for (let j = 0, i = 0; i < hex.length; i += 2, j++) {
      byteArray[j] = parseInt(hex[i] + hex[i + 1], 16);
    }
    return byteArray;
  }
}

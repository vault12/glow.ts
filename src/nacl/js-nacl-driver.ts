import { box, BoxKeyPair, randomBytes, secretbox, hash } from 'tweetnacl';

import { NaClDriver } from './nacl-driver.interface';
import { Keypair } from './keypair.interface';
import { Utils } from '../utils/utils';

/**
 * Implementation based on TweetNaCl.js: {@link https://github.com/dchest/tweetnacl-js}.
 * SHA256 is implemented using Web Crypto API (SubtleCrypto).
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
    // Use WebCrypto API in both Node.js and browser environments
    const cryptoProvider = typeof window === 'undefined' 
      ? (await import('crypto')).webcrypto
      : crypto;
    
    const hashBuffer = await cryptoProvider.subtle.digest('SHA-256', data);
    return new Uint8Array(hashBuffer);
  }

  async random_bytes(size: number): Promise<Uint8Array> {
    return randomBytes(size);
  }

  // Helper methods are based on `js-nacl` implementations
  // https://github.com/tonyg/js-nacl/blob/cc70775cfc9d68a04905ca65c7f179b33a18066e/nacl_cooked.js

  async encode_latin1(data: string): Promise<Uint8Array> {
    return Utils.encode_latin1(data);
  }

  async decode_latin1(data: Uint8Array): Promise<string> {
    return Utils.decode_latin1(data);
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

    const zeroPaddingLength = 64;
    const extendedSource = new Uint8Array(zeroPaddingLength + data.length);
    extendedSource.fill(0);
    extendedSource.set(data, zeroPaddingLength);
    return this.crypto_hash_sha256(await this.crypto_hash_sha256(extendedSource));
  }
}

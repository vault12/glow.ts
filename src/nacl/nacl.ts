import { box, BoxKeyPair, randomBytes, secretbox } from 'tweetnacl';
import { sha256 } from 'js-sha256';

import { CryptoBoxKeypair, NaClDriver } from './nacl-driver.interface';

export class Nacl implements NaClDriver {

  // Secret-key authenticated encryption (secretbox)

  crypto_secretbox_KEYBYTES = secretbox.keyLength;

  crypto_secretbox_random_nonce(): Uint8Array {
    return randomBytes(secretbox.nonceLength);
  }

  crypto_secretbox(message: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array {
    return secretbox(message, nonce, key);
  }

  crypto_secretbox_open(box: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array | null {
    return secretbox.open(box, nonce, key);
  }

  // Public-key authenticated encryption (box)

  crypto_box(message: Uint8Array, nonce: Uint8Array, pk: Uint8Array, sk: Uint8Array): Uint8Array {
    return box(message, nonce, pk, sk);
  }

  crypto_box_open(ciphertext: Uint8Array, nonce: Uint8Array, pk: Uint8Array, sk: Uint8Array): Uint8Array | null {
    return box.open(ciphertext, nonce, pk, sk);
  }

  crypto_box_random_nonce(): Uint8Array {
    return randomBytes(box.nonceLength);
  }

  crypto_box_keypair(): CryptoBoxKeypair {
    const pair: BoxKeyPair = box.keyPair();
    return {
      boxPk: pair.publicKey,
      boxSk: pair.secretKey
    };
  }

  crypto_box_keypair_from_raw_sk(key: Uint8Array): CryptoBoxKeypair {
    const pair: BoxKeyPair = box.keyPair.fromSecretKey(key);
    return {
      boxPk: pair.publicKey,
      boxSk: pair.secretKey
    };
  }

  crypto_box_keypair_from_seed(seed: Uint8Array): CryptoBoxKeypair {
    return this.crypto_box_keypair_from_raw_sk(this.crypto_hash_sha256(seed).subarray(0, box.secretKeyLength));
  }

  // Hashing

  crypto_hash_sha256(data: Uint8Array): Uint8Array {
    return this.from_hex(sha256(data));
  }

  // Randomness

  random_bytes(size: number): Uint8Array {
    return randomBytes(size);
  }

  // Helper methods are based on `js-nacl` implementations
  // https://github.com/tonyg/js-nacl/blob/cc70775cfc9d68a04905ca65c7f179b33a18066e/nacl_cooked.js

  encode_latin1(data: string): Uint8Array {
    const result = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i++) {
      const c = data.charCodeAt(i);
      if ((c & 0xff) !== c) throw { message: 'Cannot encode string in Latin1', str: data };
      result[i] = (c & 0xff);
    }
    return result;
  }

  decode_latin1(data: Uint8Array): string {
    const encoded = [];
    for (let i = 0; i < data.length; i++) {
      encoded.push(String.fromCharCode(data[i]));
    }
    return encoded.join('');
  }

  encode_utf8(data: string): Uint8Array {
    return this.encode_latin1(unescape(encodeURIComponent(data)));
  }

  decode_utf8(data: Uint8Array): string {
    return decodeURIComponent(escape(this.decode_latin1(data)));
  }

  to_hex(data: Uint8Array): string {
    const encoded = [];
    for (let i = 0; i < data.length; i++) {
      encoded.push('0123456789abcdef'[(data[i] >> 4) & 15]);
      encoded.push('0123456789abcdef'[data[i] & 15]);
    }
    return encoded.join('');
  }

  from_hex(data: string): Uint8Array {
    const result = new Uint8Array(data.length / 2);
    for (let i = 0; i < data.length / 2; i++) {
      result[i] = parseInt(data.substr(2 * i, 2), 16);
    }
    return result;
  }


  // h2(m) = sha256(sha256(64x0 + m))
  // Zero out initial sha256 block, and double hash 0-padded message
  // http://cs.nyu.edu/~dodis/ps/h-of-h.pdf
  h2(data: string): Uint8Array {
    const source = this.encode_latin1(data);
    const extendedSource = new Uint8Array(64 + source.length);
    extendedSource.fill(0);
    extendedSource.set(source, 64);
    return this.crypto_hash_sha256(this.crypto_hash_sha256(extendedSource));
  }
}

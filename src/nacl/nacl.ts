import { randomBytes, secretbox } from 'tweetnacl';

export class Nacl {
  random_bytes(size: number): Uint8Array {
    return randomBytes(size);
  }

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
}

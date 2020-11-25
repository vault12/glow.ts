import { randomBytes, secretbox, box, BoxKeyPair } from 'tweetnacl';

interface CryptoBoxKeypair {
  boxPk: Uint8Array
  boxSk: Uint8Array
}

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
}

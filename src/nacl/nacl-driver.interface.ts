export interface CryptoBoxKeypair {
  boxPk: Uint8Array
  boxSk: Uint8Array
}

export interface NaClDriver {
  crypto_secretbox_KEYBYTES: number;
  crypto_secretbox_random_nonce(): Uint8Array;
  crypto_secretbox(message: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array;
  crypto_secretbox_open(box: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array | null ;

  crypto_box(message: Uint8Array, nonce: Uint8Array, pk: Uint8Array, sk: Uint8Array): Uint8Array;
  crypto_box_open(ciphertext: Uint8Array, nonce: Uint8Array, pk: Uint8Array, sk: Uint8Array): Uint8Array | null;
  crypto_box_random_nonce(): Uint8Array;
  crypto_box_keypair(): CryptoBoxKeypair;
  crypto_box_keypair_from_raw_sk(key: Uint8Array): CryptoBoxKeypair;
  crypto_box_keypair_from_seed(seed: Uint8Array): CryptoBoxKeypair;

  crypto_hash_sha256(data: Uint8Array): Uint8Array;
  random_bytes(size: number): Uint8Array;

  encode_latin1(data: string): Uint8Array;
  decode_latin1(data: Uint8Array): string;
  encode_utf8(data: string): Uint8Array;
  decode_utf8(data: Uint8Array): string;
  to_hex(data: Uint8Array): string;
  from_hex(data: string): Uint8Array;
}
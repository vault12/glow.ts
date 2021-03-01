import { Keypair } from './keypair.interface';

export interface EncryptedMessage {
  nonce: string;
  ctext: string;
}

export interface NaClDriver {
  // Secret-key authenticated encryption (secretbox)
  crypto_secretbox_KEYBYTES: number;
  crypto_secretbox_random_nonce(): Promise<Uint8Array>;
  crypto_secretbox(message: Uint8Array, nonce: Uint8Array, key: Uint8Array): Promise<Uint8Array>;
  crypto_secretbox_open(box: Uint8Array, nonce: Uint8Array, key: Uint8Array): Promise<Uint8Array | null>;

  // Public-key authenticated encryption (box)
  crypto_box_NONCEBYTES: number;
  crypto_box(message: Uint8Array, nonce: Uint8Array, pk: Uint8Array, sk: Uint8Array): Promise<Uint8Array>;
  crypto_box_open(cipher: Uint8Array, nonce: Uint8Array, pk: Uint8Array, sk: Uint8Array): Promise<Uint8Array | null>;
  crypto_box_random_nonce(): Promise<Uint8Array>;
  crypto_box_keypair(): Promise<Keypair>;
  crypto_box_keypair_from_raw_sk(key: Uint8Array): Promise<Keypair>;
  crypto_box_keypair_from_seed(seed: Uint8Array): Promise<Keypair>;

  // Hashing
  crypto_hash_sha256(data: Uint8Array): Promise<Uint8Array>;

  // Encoding wrappers
  rawEncodeMessage(message: Uint8Array, pkTo: Uint8Array, skFrom: Uint8Array,
    nonceData?: number): Promise<EncryptedMessage>;
  /* eslint-disable @typescript-eslint/explicit-module-boundary-types, @typescript-eslint/no-explicit-any */
  rawDecodeMessage(nonce: Uint8Array, ctext: Uint8Array, pkFrom: Uint8Array, skTo: Uint8Array): Promise<any>;

  // Helpers
  random_bytes(size: number): Promise<Uint8Array>;
  encode_latin1(data: string): Promise<Uint8Array>;
  decode_latin1(data: Uint8Array): Promise<string>;
  encode_utf8(data: string): Promise<Uint8Array>;
  decode_utf8(data: Uint8Array): Promise<string>;
  to_hex(data: Uint8Array): Promise<string>;
  from_hex(data: string): Promise<Uint8Array>;

  h2(data: string | Uint8Array): Promise<Uint8Array>;
  makeNonce(data?: number): Promise<Uint8Array>;
}

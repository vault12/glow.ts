export interface CryptoBoxKeypair {
  boxPk: Uint8Array
  boxSk?: Uint8Array // secret key is optional, because we store public keys of guests in the keyring
}

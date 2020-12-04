import { Base64, Utils } from '../utils/utils';
import { CryptoBoxKeypair } from '../nacl/crypto-box-keypair.interface';

/**
 * A simple wrapper around a public/private keys pair.
 * Stores keys in base64 format.
 */
export class Keys {
  private keyPair: CryptoBoxKeypair;

  constructor(public keys: Base64 | CryptoBoxKeypair) {
    if (typeof keys === 'string') {
      const { boxPk, boxSk } = JSON.parse(keys);
      this.keyPair = {
        boxPk: Utils.fromBase64(boxPk),
        boxSk: Utils.fromBase64(boxSk)
      };
    } else {
      this.keyPair = keys;
    }
  }

  toString(): string {
    return JSON.stringify({
      boxPk: this.publicKey,
      boxSk: this.privateKey
    });
  }

  static isEqual(keys1: Keys, keys2: Keys): boolean {
    return keys1.toString() === keys2.toString();
  }

  get publicKey(): Base64 {
    return Utils.toBase64(this.keyPair.boxPk);
  }

  get privateKey(): Base64 {
    return Utils.toBase64(this.keyPair.boxSk);
  }
}

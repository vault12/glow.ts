import { NaCl } from './nacl';
import { EncryptedMessage } from './nacl-driver.interface';
import { Utils, Base64 } from '../utils/utils';

/**
 * Includes several static helpers that are build on top of basic NaCl driver methods,
 * to avoid duplicating code in driver implementations.
 */
export class EncryptionHelper {

  private constructor() { }

  /**
   * Encodes a binary message with `cryptobox`
   */
  static async encodeMessage(message: Uint8Array, pkTo: Uint8Array, skFrom: Uint8Array, nonceData?: number) {
    const nacl = NaCl.getInstance();

    const nonce = await this.makeNonce(nonceData);
    const ctext = await nacl.crypto_box(message, nonce, pkTo, skFrom);
    return {
      nonce: Utils.toBase64(nonce),
      ctext: Utils.toBase64(ctext)
    } as EncryptedMessage;
  }

  /**
   * Decodes a binary message with `cryptobox_open`
   * @returns null if failed to decode
   */
  static async decodeMessage(nonce: Uint8Array, ctext: Uint8Array, pkFrom: Uint8Array, skTo: Uint8Array) {
    const nacl = NaCl.getInstance();
    const data = await nacl.crypto_box_open(ctext, nonce, pkFrom, skTo);
    if (data) {
      return await nacl.decode_utf8(data);
    }

    return data;
  }

  /**
   * Encodes a binary message with `secretbox` (used for file chunk encryption)
   */
  static async encodeMessageSymmetric(message: Uint8Array, secretKey: Uint8Array): Promise<EncryptedMessage> {
    const nacl = NaCl.getInstance();
    const nonce = await EncryptionHelper.makeNonce();
    const ctext = await nacl.crypto_secretbox(message, nonce, secretKey);
    return {
      nonce: Utils.toBase64(nonce),
      ctext: Utils.toBase64(ctext)
    };
  }

  /**
   * Decodes a binary message with `secretbox_open` (used for file chunk decryption)
   */
  static async decodeMessageSymmetric(nonce: Base64, ctext: Base64, secretKey: Uint8Array): Promise<Uint8Array | null> {
    const nacl = NaCl.getInstance();
    return await nacl.crypto_secretbox_open(Utils.fromBase64(ctext), Utils.fromBase64(nonce), secretKey);
  }

  // ---------- Nonce helper ----------

  /**
   * Makes a timestamp nonce that a relay expects for any crypto operations.
   * Timestamp is the first 8 bytes, the rest is random, unless custom `data`
   * is specified. `data` will be packed as next 4 bytes after timestamp.
   */
  private static async makeNonce(data?: number): Promise<Uint8Array> {
    const nacl = NaCl.getInstance();
    const nonce = await nacl.crypto_box_random_nonce();
    let headerLen;
    if (nonce.length !== nacl.crypto_box_NONCEBYTES) {
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
  private static itoa(num: number): Uint8Array {
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

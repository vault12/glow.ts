import { NaClDriver, EncryptedMessage } from './nacl-driver.interface';
import { JsNaClDriver } from './js-nacl-driver';
import { Utils } from '../utils/utils';

/**
 * Facade singleton to access the NaCl driver.
 * Usage: call instance() with a chosen driver, and store the received object to perform further actions.
 *
 * Also includes several static helpers that are build on top of basic NaCl driver methods,
 * to avoid duplicating code in driver implementations.
 */
export class NaCl {
  private static driverInstance?: NaClDriver;

  private constructor() {}

  public static setInstance(driver?: NaClDriver): boolean {
    if (this.driverInstance) {
      throw new Error('[NaCl] NaCl driver has been already set, it is supposed to be set only once');
    } else {
      // fallback to the default JS driver
      this.driverInstance = driver || new JsNaClDriver();
    }

    return true;
  }

  public static getInstance(): NaClDriver {
    if (!this.driverInstance) {
      throw new Error('[NaCl] NaCl instance is not yet set');
    }

    return this.driverInstance;
  }

  // ---------- Encoding wrappers ----------

  /**
   * Encodes a binary message with `cryptobox`
   */
  static async rawEncodeMessage(message: any, pkTo: Uint8Array,
    skFrom: Uint8Array, nonceData?: number): Promise<EncryptedMessage> {
    const nacl = NaCl.getInstance();

    if (!(message instanceof Uint8Array)) {
      message = await nacl.encode_utf8(JSON.stringify(message));
    }

    const nonce = await this.makeNonce(nonceData);
    const ctext = await nacl.crypto_box(message, nonce, pkTo, skFrom);
    return {
      nonce: Utils.toBase64(nonce),
      ctext: Utils.toBase64(ctext)
    };
  }

  /**
   * Decodes a binary message with `cryptobox_open`
   */
  static async rawDecodeMessage(nonce: Uint8Array, ctext: Uint8Array, pkFrom: Uint8Array,
    skTo: Uint8Array): Promise<any> {
    const nacl = NaCl.getInstance();
    const data = await nacl.crypto_box_open(ctext, nonce, pkFrom, skTo);
    if (data) {
      const utf8 = await nacl.decode_utf8(data);
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
  static async makeNonce(data?: number): Promise<Uint8Array> {
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

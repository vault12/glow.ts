import { NaCl } from '../nacl/nacl';
import { Utils } from '../utils/utils';
import { config } from '../config';
import { StorageDriver } from './storage-driver.interface';

// TODO: add bulk operations to set(), get() and remove() pairs of values simultaneously
export class CryptoStorage {
  private driver?: StorageDriver;
  private rootKey?: string;
  private storageKey?: Uint8Array;

  static async new(storageDriver: StorageDriver, rootKey?: string): Promise<CryptoStorage> {
    const storage = new CryptoStorage();
    storage.driver = storageDriver;
    storage.storageKey = await NaCl.instance().random_bytes(NaCl.instance().crypto_secretbox_KEYBYTES);
    storage.rootKey = rootKey ? `.${rootKey}${config.STORAGE_ROOT}` : config.STORAGE_ROOT;
    return storage;
  }

  async save(tag: string, data: unknown): Promise<boolean> {
    if (!this.driver || !this.storageKey) {
      return false;
    }
    // Convert the data to JSON, then convert that string to a byte array
    const input = JSON.stringify(data);
    const encoded = await NaCl.instance().encode_utf8(input);
    // For each item in the store we also generate and save its own nonce
    const nonce = await NaCl.instance().crypto_secretbox_random_nonce();
    const cipherText = await NaCl.instance().crypto_secretbox(encoded, nonce, this.storageKey);
    // Save the cipher text and nonce
    await this.driver.set(this.addPrefix(tag), Utils.toBase64(cipherText));
    await this.driver.set(this.addPrefix(this.addNonceTag(tag)), Utils.toBase64(nonce));
    return true;
  }

  async get(tag: string): Promise<unknown> {
    if (!this.driver || !this.storageKey) {
      return false;
    }
    // Get cipher text and nonce from the storage
    const data = await this.driver.get(this.addPrefix(tag));
    const nonce = await this.driver.get(this.addPrefix(this.addNonceTag(tag)));
    // Nothing to do without cipher text or nonce
    if (!data || !nonce) {
      return null;
    }
    const dataBinary = Utils.fromBase64(data);
    const nonceBinary = Utils.fromBase64(nonce);
    const source = await NaCl.instance().crypto_secretbox_open(dataBinary, nonceBinary, this.storageKey);
    if (source) {
      const decoded = await NaCl.instance().decode_utf8(source);
      return JSON.parse(decoded);
    } else {
      return null;
    }
  }

  async remove(tag: string): Promise<boolean> {
    if (!this.driver) {
      return false;
    }
    await this.driver.remove(this.addPrefix(tag));
    await this.driver.remove(this.addPrefix(this.addNonceTag(tag)));
    return true;
  }

  // Keys are tagged in the storage with a versioned prefix
  private addPrefix(key: string): string {
    return this.rootKey ? (key + this.rootKey) : key;
  }

  private addNonceTag(tag: string): string {
    return `${config.NONCE_TAG}.${tag}`;
  }
}

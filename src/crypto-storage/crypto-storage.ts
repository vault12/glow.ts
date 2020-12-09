import { NaCl } from '../nacl/nacl';
import { Utils } from '../utils/utils';
import { config } from '../config';
import { StorageDriver } from './storage-driver.interface';
import { NaClDriver } from '../nacl/nacl-driver.interface';

// TODO: add bulk operations to set(), get() and remove() pairs of values simultaneously
export class CryptoStorage {
  private driver?: StorageDriver;
  private rootKey?: string;
  private storageKey?: Uint8Array;
  private nacl: NaClDriver;

  private constructor(naclDriver: NaClDriver) {
    this.nacl = naclDriver;
  }

  static async new(storageDriver: StorageDriver, rootKey?: string): Promise<CryptoStorage> {
    const nacl = NaCl.instance();
    const storage = new CryptoStorage(nacl);
    storage.driver = storageDriver;
    storage.storageKey = await nacl.random_bytes(nacl.crypto_secretbox_KEYBYTES);
    storage.rootKey = rootKey ? `.${rootKey}${config.STORAGE_ROOT}` : config.STORAGE_ROOT;
    return storage;
  }

  async save(tag: string, data: unknown): Promise<boolean> {
    if (!this.driver) {
      throw new Error('Storage driver is not set');
    }
    if (!this.storageKey) {
      throw new Error('Storage key is not set');
    }
    // Convert the data to JSON, then convert that string to a byte array
    const input = JSON.stringify(data);
    const encoded = await this.nacl.encode_utf8(input);
    // For each item in the store we also generate and save its own nonce
    const nonce = await this.nacl.crypto_secretbox_random_nonce();
    const cipherText = await this.nacl.crypto_secretbox(encoded, nonce, this.storageKey);
    // Save the cipher text and nonce
    await this.driver.set(this.addPrefix(tag), Utils.toBase64(cipherText));
    await this.driver.set(this.addNonceTag(tag), Utils.toBase64(nonce));
    return true;
  }

  async get(tag: string): Promise<unknown> {
    if (!this.driver) {
      throw new Error('Storage driver is not set');
    }
    if (!this.storageKey) {
      throw new Error('Storage key is not set');
    }
    // Get cipher text and nonce from the storage
    const data = await this.driver.get(this.addPrefix(tag));
    const nonce = await this.driver.get(this.addNonceTag(tag));
    // Nothing to do without cipher text or nonce
    if (!data || !nonce) {
      return null;
    }
    const dataBinary = Utils.fromBase64(data);
    const nonceBinary = Utils.fromBase64(nonce);
    const source = await this.nacl.crypto_secretbox_open(dataBinary, nonceBinary, this.storageKey);
    if (source) {
      const decoded = await this.nacl.decode_utf8(source);
      return JSON.parse(decoded);
    } else {
      throw new Error('crypto_secretbox_open: decryption error');
    }
  }

  async remove(tag: string): Promise<boolean> {
    if (!this.driver) {
      throw new Error('Storage driver is not set');
    }
    await this.driver.remove(this.addPrefix(tag));
    await this.driver.remove(this.addNonceTag(tag));
    return true;
  }

  // Keys are tagged in the storage with a versioned prefix
  private addPrefix(key: string): string {
    return this.rootKey ? (key + this.rootKey) : key;
  }

  private addNonceTag(tag: string): string {
    return this.addPrefix(`${config.NONCE_TAG}.${tag}`);
  }
}

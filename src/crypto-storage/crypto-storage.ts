import { NaCl } from '../nacl/nacl';
import { Utils } from '../utils/utils';
import { config } from '../config';
import { StorageDriver } from './storage-driver.interface';
import { NaClDriver } from '../nacl/nacl-driver.interface';
import { LocalStorageDriver } from './local-storage.driver';

// TODO: add bulk operations to set(), get() and remove() pairs of values simultaneously

/* CryptoStorage is a handy wrapper around any storage that provides JavaScript interface,
   that allows to store symmetrically encrypted serializable Javascript objects and primitives. */
export class CryptoStorage {

  private static storageDriver: StorageDriver;

  private driver?: StorageDriver;
  private id?: string;
  private storageKey?: Uint8Array;
  private nacl: NaClDriver;

  private constructor(storageDriver: StorageDriver, id: string) {
    const nacl = NaCl.getInstance();
    this.nacl = nacl;
    this.driver = storageDriver;
    this.id = id ? `.${id}${config.STORAGE_ROOT}` : config.STORAGE_ROOT;
  }

  static async new(id: string): Promise<CryptoStorage> {
    const storageDriver = this.getStorageDriver();
    const storage = new CryptoStorage(storageDriver, id);
    const prefixedStorageKeyTag = storage.addPrefix(config.SKEY_TAG);
    const storageKey = await storageDriver.get(prefixedStorageKeyTag);
    // Either load or generate a storage key
    if (storageKey) {
      const { key } = JSON.parse(storageKey);
      storage.storageKey = Utils.fromBase64(key);
    } else {
      storage.storageKey = await storage.nacl.random_bytes(storage.nacl.crypto_secretbox_KEYBYTES);
      await storageDriver.set(prefixedStorageKeyTag, JSON.stringify({ key: Utils.toBase64(storage.storageKey)}));
    }
    return storage;
  }

  static getStorageDriver() {
    if (!this.storageDriver) {
      throw new Error('[CryptoStorage] StorageDriver instance is not yet set');
    } else {
      return this.storageDriver;
    }
  }

  static setDefaultStorageDriver() {
    return this.setStorageDriver(new LocalStorageDriver());
  }

  static setStorageDriver(driver: StorageDriver) {
    if (this.storageDriver) {
      throw new Error('[CryptoStorage] StorageDriver has been already set, it is supposed to be set only once');
    }
    this.storageDriver = driver;
    return true;
  }

  async save(tag: string, data: unknown): Promise<boolean> {
    if (!this.driver) {
      throw new Error('[CryptoStorage] Storage driver is not set');
    }
    if (!this.storageKey) {
      throw new Error('[CryptoStorage] Storage key is not set');
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
      throw new Error('[CryptoStorage] Storage driver is not set');
    }
    if (!this.storageKey) {
      throw new Error('[CryptoStorage] Storage key is not set');
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
      throw new Error('[CryptoStorage] crypto_secretbox_open: decryption error');
    }
  }

  async remove(tag: string): Promise<boolean> {
    if (!this.driver) {
      throw new Error('[CryptoStorage] Storage driver is not set');
    }
    await this.driver.remove(this.addPrefix(tag));
    await this.driver.remove(this.addNonceTag(tag));
    return true;
  }

  async selfDestruct() {
    if (!this.driver) {
      throw new Error('[CryptoStorage] Storage driver is not set');
    }
    await this.driver.remove(this.addPrefix(config.SKEY_TAG));
  }

  // Keys are tagged in the storage with a versioned prefix
  private addPrefix(key: string): string {
    return this.id ? (key + this.id) : key;
  }

  private addNonceTag(tag: string): string {
    return this.addPrefix(`${config.NONCE_TAG}.${tag}`);
  }
}

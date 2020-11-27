import { Nacl } from '../nacl/nacl';
import { Utils } from '../utils/utils';
import { config } from '../config';
import { StorageDriver } from './storage-driver.interface';

export class CryptoStorage {
  private driver: StorageDriver;
  private rootKey = '';
  private storageKey: Uint8Array;

  constructor(public storageDriver: StorageDriver) {
    this.driver = storageDriver;
    const nacl = new Nacl();
    this.storageKey = nacl.random_bytes(nacl.crypto_secretbox_KEYBYTES);
  }

  // Keys are tagged in the storage with a versioned prefix
  tag(key: string): string {
    return this.rootKey.length ? (key + this.rootKey) : key;
  }

  async save(tag: string, data: unknown): Promise<void> {
    const input = JSON.stringify(data);
    const nacl = new Nacl();
    const encoded = nacl.encode_utf8(input);
    const nonce = nacl.crypto_secretbox_random_nonce();
    const cipherText = nacl.crypto_secretbox(encoded, nonce, this.storageKey);
    this.driver.set(tag, Utils.toBase64(Utils.decode_latin1(cipherText)));
    this.driver.set(`${config.NONCE_TAG}.${tag}`, Utils.toBase64(Utils.decode_latin1(nonce)));
  }
}

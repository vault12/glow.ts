import { StorageDriver } from './storage-driver.interface';

/**
 * temporary created in-memory storage for testing purposes
 */
export class InMemoryStorage implements StorageDriver {
  private storage: {[key: string]: any} = {};
  get(key: string) {
    return Promise.resolve(this.storage[key]);
  }
  set (key: string, value: any) {
    this.storage[key] = value;
    return Promise.resolve();
  }
  remove(key: string) {
    delete this.storage[key];
    return Promise.resolve();
  }
  reset() {
    this.storage = {};
  }
}
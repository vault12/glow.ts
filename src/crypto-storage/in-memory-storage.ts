import { StorageDriver } from './storage-driver.interface';

/**
 * temporary created in-memory storage for testing purposes
 */
export class InMemoryStorage implements StorageDriver {

  private storage: {[key: string]: string|null} = {};

  async get(key: string) {
    return (await this.getMultiple([key]))[0];
  }

  async getMultiple(keys: string[]) {
    return keys.map(key => this.storage[key]);
  }

  set<T extends string | null>(key: string, value: T) {
    return this.setMultiple({[key]: value});
  }

  async setMultiple<T extends string | null>(values: { [key: string]: T; }){
    for (const key in values) {
      this.storage[key] = values[key];
    }
  }

  remove(key: string) {
    return this.removeMultiple([key]);
  }

  async removeMultiple(keys: string[]) {
    keys.forEach(key => delete this.storage[key]);
  }

  reset() {
    this.storage = {};
  }
}
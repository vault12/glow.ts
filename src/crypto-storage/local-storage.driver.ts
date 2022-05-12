import { StorageDriver } from './storage-driver.interface';

export class LocalStorageDriver implements StorageDriver {
  private rootTag: string;

  constructor(root = 'storage.') {
    this.rootTag = `__glow.${root}`;
  }

  async get(key: string): Promise<string | null> {
    return (await this.getMultiple([key]))[0];
  }

  async getMultiple(keys: string[]): Promise<(string | null)[]> {
    return keys.map(key => localStorage.getItem(this.tag(key)) || null);
  }

  async set(key: string, value: string | null): Promise<void> {
    return this.setMultiple({ [key]: value });
  }

  async setMultiple(values: { [key: string]: string | null; }): Promise<void> {
    for(const key in values) {
      const value = values[key];
      if (value !== null) {
        localStorage.setItem(this.tag(key), value);
      }
    }
  }

  async remove(key: string): Promise<void> {
    this.removeMultiple([key]);
  }

  async removeMultiple(keys: string[]): Promise<void> {
    keys.forEach(key => localStorage.removeItem(this.tag(key)));
  }

  private tag(key: string) {
    return `${this.rootTag}.${key}`;
  }
}

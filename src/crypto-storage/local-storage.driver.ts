import { StorageDriver } from './storage-driver.interface';

export class LocalStorageDriver implements StorageDriver {
  private rootTag: string;

  constructor(root = 'storage.') {
    this.rootTag = `__glow.${root}`;
  }

  async get(key: string): Promise<string | null> {
    const item = localStorage.getItem(this.tag(key));
    return item ? item : null;
  }

  async set(key: string, value: string | null): Promise<void> {
    if (value !== null) {
      localStorage.setItem(this.tag(key), value);
    }
  }

  async remove(key: string): Promise<void> {
    localStorage.removeItem(this.tag(key));
  }

  private tag(key: string) {
    return `${this.rootTag}.${key}`;
  }
}

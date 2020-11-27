import { StorageDriver } from './storage-driver.interface';

export class LocalStorageDriver implements StorageDriver {
  private rootTag: string;

  constructor(root = 'storage.') {
    this.rootTag = `__glow.${root}`;
  }

  async get(key: string): Promise<unknown> {
    const item = localStorage.getItem(this.tag(key));
    return item ? JSON.parse(item) : null;
  }

  async set(key: string, value: unknown): Promise<void> {
    localStorage.setItem(this.tag(key), JSON.stringify(value));
  }

  async remove(key: string): Promise<void> {
    localStorage.removeItem(this.tag(key));
  }

  private tag(key: string) {
    return `${this.rootTag}.${key}`;
  }
}

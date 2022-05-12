export interface StorageDriver {
  get(key: string): Promise<string | null>;
  getMultiple(keys: string[]): Promise<(string | null)[]>;
  set(key: string, value: string | null): Promise<void>;
  setMultiple(values: {[key: string]: string | null}): Promise<void>;
  remove(key: string): Promise<void>;
  removeMultiple(keys: string[]): Promise<void>;
}

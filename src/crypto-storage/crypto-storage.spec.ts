import { CryptoStorage } from './crypto-storage';
import { LocalStorageDriver } from './local-storage.driver';

describe('CryptoStorage', () => {
  let storage: CryptoStorage;

  beforeEach(() => {
    storage = new CryptoStorage(new LocalStorageDriver());
  });

  it('save/read', async () => {
    const object = { field1: 'string value', field2: 101 };
    await storage.save('test', object);
    const restored = await storage.get('test');
    expect(JSON.stringify(object)).toBe(JSON.stringify(restored));
  });
});

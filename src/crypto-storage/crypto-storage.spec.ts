import { CryptoStorage } from './crypto-storage';
import { LocalStorageDriver } from './local-storage.driver';

describe('CryptoStorage', () => {
  let storage: CryptoStorage;

  beforeEach(() => {
    storage = new CryptoStorage(new LocalStorageDriver());
  });

  it.only('storage', async () => {
    await storage.save('test', '42');
    const wha = await storage.get('test');
    console.log(wha);
  });
});

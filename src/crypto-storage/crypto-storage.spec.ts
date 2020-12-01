import { CryptoStorage } from './crypto-storage';
import { LocalStorageDriver } from './local-storage.driver';

describe('CryptoStorage', () => {
  let storage: CryptoStorage;

  beforeEach(() => {
    storage = new CryptoStorage(new LocalStorageDriver());
  });

  it('encrypted write/read', async () => {
    const secretPlaintext = 'The quick brown fox jumps over the lazy dog';
    const secretObject = {
      field1: 'string value', // String
      field2: 101, // Number
      field3: { // Object
        inside: 'secret'
      },
      field4: [1, 2, 3, 'big', 'secrets'], // Array
      field5: 'Kæmi ný öxi hér ykist þjófum nú bæði víl og ádrepa' // Unicode string in Icelandic
    };

    await storage.save('secretPlaintext', secretPlaintext);
    const restoredPlaintext = await storage.get('secretPlaintext');
    expect(secretPlaintext).toBe(restoredPlaintext);

    await storage.save('secretObject', secretObject);
    const restoredObject = await storage.get('secretObject');
    expect(JSON.stringify(secretObject)).toBe(JSON.stringify(restoredObject));

    await storage.remove('secretPlaintext');
    await storage.remove('secretObject');

    const notRestoredPlaintext = await storage.get('secretPlaintext');
    const notRestoredObject = await storage.get('secretObject');
    expect(notRestoredPlaintext).toBeNull();
    expect(notRestoredObject).toBeNull();
  });
});

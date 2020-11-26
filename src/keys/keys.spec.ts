import { Keys } from './keys';

describe('Keys', () => {
  let fromBinary: Keys;
  let fromSerialized: Keys;

  beforeEach(() => {
    fromBinary = new Keys({
      boxPk: new Uint8Array([1, 2, 3]),
      boxSk: new Uint8Array([4, 5, 6])
    });

    fromSerialized = new Keys(fromBinary.toString());
  });

  it('should create identical keys from binary and serialized input', () => {
    expect(fromBinary.privateKey).toBe(fromSerialized.privateKey);
    expect(fromBinary.publicKey).toBe(fromSerialized.publicKey);
    expect(Keys.isEqual(fromBinary, fromSerialized)).toBe(true);
  });
});

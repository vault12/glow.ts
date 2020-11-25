import { Keys } from './keys';

describe('Keys', () => {
  let keys: Keys;

  beforeEach(() => {
    keys = new Keys('test');
  });

  it('should return base64', () => {
    const actual = keys.toBase64();
    const expected = 'dGVzdA==';

    expect(actual).toBe(expected);
  });

  it('should return source', () => {
    const spyWarn = jest.spyOn(console, 'log');
    const input = 'd2hhdCBpcyBsb3Zl';
    const actual = keys.fromBase64(input);
    const expected = 'what is love';

    expect(actual).toBe(expected);
    expect(spyWarn).toHaveBeenCalledWith(`decrypting ${input}...`);
  });
});

import { Utils } from './utils';

describe('Utils', () => {
  it('should return base64', () => {
    const actual = Utils.toBase64('test');
    const expected = 'dGVzdA==';

    expect(actual).toBe(expected);
  });

  it('should return source', () => {
    const input = 'd2hhdCBpcyBsb3Zl';
    const actual = Utils.fromBase64(input);
    const expected = 'what is love';

    expect(actual).toBe(expected);
  });
});

import { Utils } from './utils';

describe('Utils', () => {
  it('should return base64', () => {
    const actual = Utils.toBase64(Utils.encode_latin1('test'));
    const expected = 'dGVzdA==';

    expect(actual).toBe(expected);
  });

  it('should return source', () => {
    const input = 'd2hhdCBpcyBsb3Zl';
    const actual = Utils.decode_latin1(Utils.fromBase64(input));
    const expected = 'what is love';

    expect(actual).toBe(expected);
  });

  ['some message', 'special ;@@#2sd characters'].forEach(msg => {
    it('do to and from base64 for ' + msg, () => {
      const base64 = Utils.toBase64(Utils.encode_latin1(msg));
      expect(Utils.decode_latin1(Utils.fromBase64(base64))).toEqual(msg);
    });
  });
});

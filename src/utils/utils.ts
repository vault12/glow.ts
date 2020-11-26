export type Base64 = string;

export class Utils {
  static toBase64(input: string): Base64 {
    const isBrowser = typeof btoa !== 'undefined';
    return isBrowser ? btoa(input) : Buffer.from(input, 'utf-8').toString('base64');
  }

  static fromBase64(input: Base64): string {
    const isBrowser = typeof btoa !== 'undefined';
    return isBrowser ? atob(input) : Buffer.from(input, 'base64').toString('utf-8');
  }

  static encode_latin1(data: string): Uint8Array {
    const result = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i++) {
      const c = data.charCodeAt(i);
      if ((c & 0xff) !== c) throw { message: 'Cannot encode string in Latin1', str: data };
      result[i] = (c & 0xff);
    }
    return result;
  }

  static decode_latin1(data: Uint8Array): string {
    const encoded = [];
    for (let i = 0; i < data.length; i++) {
      encoded.push(String.fromCharCode(data[i]));
    }
    return encoded.join('');
  }

}

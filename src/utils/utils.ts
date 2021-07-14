export type Base64 = string;

export class Utils {
  static toBase64(input: Uint8Array): Base64 {
    const isBrowser = typeof btoa !== 'undefined';
    return isBrowser ?
      btoa(this.decode_latin1(input)) :
      Buffer.from(this.decode_latin1(input), 'latin1').toString('base64');
  }

  static fromBase64(input: Base64): Uint8Array {
    const isBrowser = typeof btoa !== 'undefined';
    return isBrowser ?
      this.encode_latin1(atob(input)) :
      this.encode_latin1(Buffer.from(input, 'base64').toString('latin1'));
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

  static toObject(pairs: IterableIterator<[string, any]>) {
    return Array.from(pairs).reduce(
      (acc, [key, value]) => Object.assign(acc, { [key]: value }),
      {},
    );
  }
}

export class Keys {
  hashKeys: string;

  constructor(public keys: string) {
    this.hashKeys = keys;
  }

  toBase64(): string {
    const isBrowser = typeof btoa !== 'undefined';
    return isBrowser ? btoa(this.hashKeys) : Buffer.from(this.hashKeys, 'utf-8').toString('base64');
  }

  fromBase64(input: string): string {
    const isBrowser = typeof btoa !== 'undefined';
    this.hashKeys = isBrowser ? atob(input) : Buffer.from(input, 'base64').toString('utf-8');
    console.log(`decrypting ${input}...`);
    return this.hashKeys;
  }
}

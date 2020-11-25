import { Nacl } from './nacl';

describe('Nacl', () => {
  let nacl: Nacl;

  beforeEach(() => {
    nacl = new Nacl();
  });

  it('random_bytes', () => {
    const actual = nacl.random_bytes(5);
    expect(actual.length).toBe(5);
  });

  it('crypto_secretbox', () => {
    const input = new Uint8Array([1,2,3]);
    const nonce = nacl.crypto_secretbox_random_nonce();
    const key = nacl.random_bytes(nacl.crypto_secretbox_KEYBYTES);
    const encrypted = nacl.crypto_secretbox(input, nonce, key);
    const decrypted = nacl.crypto_secretbox_open(encrypted, nonce, key);
    expect(decrypted).toEqual(input);
  });
});

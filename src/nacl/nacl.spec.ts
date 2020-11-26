import { Nacl } from './nacl';

describe('Nacl', () => {
  let nacl: Nacl;

  beforeEach(() => {
    nacl = new Nacl();
  });

  it('crypto_secretbox', () => {
    const input = nacl.random_bytes(1000);
    const nonce = nacl.crypto_secretbox_random_nonce();
    const key = nacl.random_bytes(nacl.crypto_secretbox_KEYBYTES);
    const encrypted = nacl.crypto_secretbox(input, nonce, key);
    const decrypted = nacl.crypto_secretbox_open(encrypted, nonce, key);
    expect(decrypted).toEqual(input);
  });

  it('crypto_hash_sha256', () => {
    expect(nacl.to_hex(nacl.crypto_hash_sha256(nacl.encode_utf8('hello'))))
      .toBe('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
  });

  it('random_bytes', () => {
    const actual = nacl.random_bytes(5);
    expect(actual.length).toBe(5);
  });

  it('hex encoding', () => {
    expect(nacl.to_hex(nacl.encode_utf8('hello'))).toBe('68656c6c6f');

    expect(nacl.decode_utf8(nacl.from_hex('68656c6c6f'))).toBe('hello');
    expect(nacl.decode_utf8(nacl.from_hex('68656C6C6F'))).toBe('hello');
  });
});

import { NaCl } from './nacl';
import { NaClDriver } from './nacl-driver.interface';
import { Utils } from '../utils/utils';

describe('NaCl', () => {
  let nacl: NaClDriver;

  beforeEach(() => {
    nacl = NaCl.instance();
  });

  it('crypto_secretbox', async () => {
    const input = await nacl.random_bytes(1000);
    const nonce = await nacl.crypto_secretbox_random_nonce();
    const key = await nacl.random_bytes(nacl.crypto_secretbox_KEYBYTES);
    const encrypted = await nacl.crypto_secretbox(input, nonce, key);
    const decrypted = await nacl.crypto_secretbox_open(encrypted, nonce, key);
    expect(decrypted).toEqual(input);
  });

  it('crypto_box_keypair', async () => {
    const keys = await nacl.crypto_box_keypair();
    expect(keys.boxPk).toBeTruthy();
    expect(keys.boxSk).toBeTruthy();
    expect(keys.boxPk).not.toEqual(keys.boxSk);
    expect(keys.boxPk.length).toBe(keys.boxSk.length);
  });

  it('crypto_box', async () => {
    const alice = await nacl.crypto_box_keypair();
    const bob = await nacl.crypto_box_keypair();
    const nonce = await nacl.crypto_box_random_nonce();

    const message = await nacl.random_bytes(100);

    const aliceEncryptedMessage = await nacl.crypto_box(message, nonce, bob.boxPk, alice.boxSk);
    const bobDecryptedMessage = await nacl.crypto_box_open(aliceEncryptedMessage, nonce, alice.boxPk, bob.boxSk);
    expect(bobDecryptedMessage).toEqual(message);
  });

  it('crypto_box_keypair_from_raw_sk', async () => {
    const keys = await nacl.crypto_box_keypair();
    const restoredKeys = await nacl.crypto_box_keypair_from_raw_sk(keys.boxSk);
    expect(keys.boxPk).toEqual(restoredKeys.boxPk);
    expect(keys.boxSk).toEqual(restoredKeys.boxSk);
  });

  it('crypto_box_keypair_from_seed', async () => {
    const input = new Uint8Array([1,2,3]);
    const keysFromSeed = await nacl.crypto_box_keypair_from_seed(input);
    expect(Utils.toBase64(Utils.decode_latin1(keysFromSeed.boxPk)))
      .toEqual('yprjMh3kE7/6+wrju7aehal7g88mZ9jK1818dPdhwB4=');
    expect(Utils.toBase64(Utils.decode_latin1(keysFromSeed.boxSk)))
      .toEqual('J4ZMxSGalRp6blK4yN3faYHQmNoWWNliWMhwssiN+8s=');
  });

  it('crypto_hash_sha256', async () => {
    expect(await nacl.to_hex(await nacl.crypto_hash_sha256(await nacl.encode_utf8('hello'))))
      .toBe('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
  });

  it('random_bytes', async () => {
    const actual = await nacl.random_bytes(5);
    expect(actual.length).toBe(5);
  });

  it('hex encoding', async () => {
    expect(await nacl.to_hex(await nacl.encode_utf8('hello'))).toBe('68656c6c6f');

    expect(await nacl.decode_utf8(await nacl.from_hex('68656c6c6f'))).toBe('hello');
    expect(await nacl.decode_utf8(await nacl.from_hex('68656C6C6F'))).toBe('hello');
  });

  it('hash₂ of utf8 strings', async () => {
    const h2 = await nacl.h2('Heizölrückstoßabdämpfung');
    expect(await nacl.to_hex(h2)).toBe('6f1d7a58b6ea177040f9bf6056913ddacef2bacff0c84b8c07d9dc01e27e147f');
  });
});

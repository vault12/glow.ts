import { KeyRing } from './keyring';
import { NaCl } from '../nacl/nacl';
import { NaClDriver } from '../nacl/nacl-driver.interface';
import { Keys } from '../keys/keys';
import { Utils } from '../utils/utils';

describe('Keyring', () => {
  let nacl: NaClDriver;

  beforeAll(() => {
    NaCl.setInstance();
    nacl = NaCl.getInstance();
  });

  it('add/remove guests', async () => {
    const ring = await KeyRing.new('test1');

    const keys1 = new Keys(await nacl.crypto_box_keypair());
    const keys2 = new Keys(await nacl.crypto_box_keypair());

    await ring.addGuest('Alice', keys1.publicKey);
    expect(ring.getNumberOfGuests()).toBe(1);
    expect(ring.getGuestKey('Alice')).toBeDefined();

    await ring.addGuest('Bob', keys2.publicKey);
    expect(ring.getNumberOfGuests()).toBe(2);
    expect(ring.getGuestKey('Bob')).toBeDefined();

    await ring.removeGuest('Alice');
    expect(ring.getNumberOfGuests()).toBe(1);
    expect(ring.getGuestKey('Alice')).toBeNull();
    expect(ring.getGuestKey('Bob')).toBeDefined();
  });

  it('create equal keys', async () => {
    const ring = await KeyRing.new('test-equal');
    const ring2 = await KeyRing.new('test-equal');
    expect(ring.getPubCommKey()).toBe(ring2.getPubCommKey());
  });

  it('get tags and keys', async() => {
    const ring = await KeyRing.new('test2');
    const commKey = ring.getPubCommKey();
    expect(typeof commKey).toBe('string');

    const aliceKey = new Keys(await nacl.crypto_box_keypair());
    await ring.addGuest('Alice', aliceKey.publicKey);
    const hpk = Utils.toBase64(await nacl.h2(Utils.fromBase64(aliceKey.publicKey)));
    expect(ring.getTagByHpk(hpk)).not.toBeNull();
    expect(ring.getTagByHpk('Bob')).toBeNull();
  });

  it('backup and restore', async () => {
    const originalRing = await KeyRing.new('test3');
    for (let i = 0; i < 10; i++) {
      const keys = new Keys(await nacl.crypto_box_keypair());
      await originalRing.addGuest(`keys${i}`, keys.publicKey);
    }

    const backup = await originalRing.backup();

    const restored = await KeyRing.fromBackup('test4', backup);
    const backedUpAgain = await restored.backup();

    expect(originalRing.getPubCommKey()).toEqual(restored.getPubCommKey());
    for (let i = 0; i < 10; i++) {
      expect(originalRing.getGuestKey(`keys${i}`)).toEqual(restored.getGuestKey(`keys${i}`));
    }
    expect(await originalRing.getHpk()).toEqual(await restored.getHpk());

    expect(backup).toBe(backedUpAgain);
  });
});

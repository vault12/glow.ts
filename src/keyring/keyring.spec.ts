import { KeyRing } from './keyring';
import { Nacl } from '../nacl/nacl';
import { Keys } from '../keys/keys';
import { config } from '../config';

describe('Keyring', () => {
  let ring1: KeyRing;
  let ring2: KeyRing;
  let nacl: Nacl;

  beforeEach(async () => {
    ring1 = await KeyRing.new();
    ring2 = await KeyRing.new();
    nacl = new Nacl();
  });

  it('add guests', async () => {
    const keys1 = new Keys(nacl.crypto_box_keypair());
    const keys2 = new Keys(nacl.crypto_box_keypair());

    await ring1.addGuest('Alice', keys1.publicKey);
    expect(ring1.getNumberOfGuests()).toBe(1);
    expect(ring1.guestKeys.get('Alice')).not.toBeNull();

    await ring1.addGuest('Bob', keys2.publicKey);
    expect(ring1.getNumberOfGuests()).toBe(2);
    expect(ring1.guestKeys.get('Bob')).not.toBeNull();
  });

  it('backup and restore', async () => {
    const originalRing = await KeyRing.new();
    for (let i = 0; i < 10; i++) {
      const keys = new Keys(nacl.crypto_box_keypair());
      await originalRing.addGuest(`keys${i}`, keys.publicKey);
    }

    const backup = await originalRing.backup();

    const restored = await KeyRing.fromBackup('id', backup);
    const backedUpAgain = await restored.backup();

    expect(originalRing.commKey).toEqual(restored.commKey);
    expect(originalRing.guestKeys).toEqual(restored.guestKeys);
    expect(originalRing.hpk).toEqual(restored.hpk);

    expect(backup).toBe(backedUpAgain);
  });

  it('temporary keys', async () => {
    jest.useFakeTimers();
    // mock config value
    config.RELAY_SESSION_TIMEOUT = 5;
    const ring = await KeyRing.new();
    const keys = new Keys(nacl.crypto_box_keypair());
    await ring.addTempGuest('temp', keys.publicKey);
    // the key has to exist before we run the timer
    expect(ring.getGuestKey('temp')).not.toBeNull();
    jest.runAllTimers();

    expect(setTimeout).toHaveBeenCalledTimes(1);
    expect(setTimeout).toHaveBeenLastCalledWith(expect.any(Function), 5);
    // the key is erased
    expect(ring.getNumberOfGuests()).toBe(0);
  });
});

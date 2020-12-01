import { KeyRing } from './keyring';
import { Nacl } from '../nacl/nacl';
import { Keys } from '../keys/keys';

describe.only('Keyring', () => {
  let ring1: KeyRing;
  let ring2: KeyRing;
  let nacl: Nacl;

  beforeEach(() => {
    ring1 = new KeyRing();
    ring2 = new KeyRing();
    nacl = new Nacl();
  });

  it('add guests', async () => {
    const keys1 = new Keys(nacl.crypto_box_keypair());
    const keys2 = new Keys(nacl.crypto_box_keypair());

    await ring1.addGuest('Alice', keys1.publicKey);
    expect(ring1.getNumberOfGuests()).toBe(1);
    expect(ring1.guestKeys['Alice']).not.toBeNull();

    await ring1.addGuest('Bob', keys2.publicKey);
    expect(ring1.getNumberOfGuests()).toBe(2);
    expect(ring1.guestKeys['Bob']).not.toBeNull();
  });
});

import { Mailbox } from './mailbox';
import { NaCl } from '../nacl/nacl';

describe('Mailbox', () => {
  let Alice: Mailbox;
  let Bob: Mailbox;
  let message1: any;
  let message2: any;

  beforeAll(async () => {
    NaCl.setInstance();
    Alice = await Mailbox.new('Alice');
    Bob = await Mailbox.new('Bob');
  });

  it('exchange keys', async () => {
    if (!Alice.keyRing || !Bob.keyRing) {
      throw new Error();
    }

    expect(Alice.keyRing.getNumberOfGuests()).toBe(0);
    expect(Alice.keyRing.getGuestKey('Bob_mbx')).toBeNull();
    await Alice.keyRing.addGuest('Bob_mbx', Bob.getPubCommKey() || '');
    expect(Alice.keyRing.getNumberOfGuests()).toBe(1);
    expect(Alice.keyRing.getGuestKey('Bob_mbx')).not.toBeNull();

    expect(Bob.keyRing.getNumberOfGuests()).toBe(0);
    expect(Bob.keyRing.getGuestKey('Alice_mbx')).toBeNull();
    await Bob.keyRing.addGuest('Alice_mbx', Alice.getPubCommKey() || '');
    expect(Bob.keyRing.getNumberOfGuests()).toBe(1);
    expect(Bob.keyRing.getGuestKey('Alice_mbx')).not.toBeNull();
  });

  it('encrypt message', async () => {
    message1 = await Alice.encodeMessage('Bob_mbx', new Uint8Array([1, 2, 3, 4]));
    message2 = await Bob.encodeMessage('Alice_mbx', new Uint8Array([5, 6, 7, 8]));
  });

  it('decrypt message', async () => {
    const decoded1 = await Bob.decodeMessage('Alice_mbx', message1.nonce, message1.ctext);
    const decoded2 = await Alice.decodeMessage('Bob_mbx', message2.nonce, message2.ctext);
    console.log(decoded1);
    console.log(decoded2);
  });
});

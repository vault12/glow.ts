import { Mailbox } from './mailbox';
import { NaCl } from '../nacl/nacl';

describe('Mailbox', () => {
  let Alice: Mailbox;
  let Bob: Mailbox;

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

  it('encrypts & decrypts strings between mailboxes', async () => {
    const utfSource1 = 'Bob, I heard from Наталья Дубровская we have a problem with the water chip.';
    const utfSource2 = 'Alice, I will dispatch one of the youngsters to find a replacement outside. नमस्ते!';

    const message1 = await Alice.encodeMessage('Bob_mbx', utfSource1);
    const message2 = await Bob.encodeMessage('Alice_mbx', utfSource2);

    const decoded1 = await Bob.decodeMessage('Alice_mbx', message1.nonce, message1.ctext);
    const decoded2 = await Alice.decodeMessage('Bob_mbx', message2.nonce, message2.ctext);
    expect(decoded1).toEqual(utfSource1);
    expect(decoded2).toEqual(utfSource2);
  });

  it('encrypts raw binary data', async () => {
    const message = await Alice.encodeMessage('Bob_mbx', new Uint8Array([1, 2, 3, 4]));
    expect(message.nonce).toHaveLength(24);
    expect(message.ctext).toHaveLength(20);
  });
});

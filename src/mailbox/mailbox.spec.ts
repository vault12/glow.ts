import { Mailbox } from './mailbox';
import { NaCl } from '../nacl/nacl';
import { Utils } from '../utils/utils';

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

  it('Mailbox from a well known seed', async () => {
    const mbx = await Mailbox.fromSeed('from_seed', Utils.encode_latin1('hello'));
    expect(mbx.keyRing?.getPubCommKey()).toBe('2DM+z1PaxGXVnzsDh4zv+IlH7sV8llEFoEmg9fG3pRA=');
    expect(mbx.keyRing?.hpk).toEqual(
      new Uint8Array([249, 209, 90, 99, 252, 44, 187, 27, 13, 101, 229, 199, 235, 31, 235, 119, 224, 25,
        207, 215, 94, 130, 71, 230, 44, 22, 217, 0, 201, 41, 61, 222]));
  });

  it('Mailbox backup & restore', async () => {
    const pubCommKey = 'vye4sj8BKHopBVXUfv3s3iKyP6TyNoJnHUYWCMcjwTo=';
    const hpk = new Uint8Array([36, 36, 36, 231, 132, 114, 39, 6, 230, 153, 228, 128, 132,
      215, 100, 241, 87, 187, 9, 53, 179, 248, 176, 242, 249, 101, 68, 48, 48, 9, 219, 211]);

    const mbx = await Mailbox.fromSeed('from_seed2', Utils.encode_latin1('hello2'));
    if (!mbx.keyRing) {
      throw new Error('no keyRing');
    }

    expect(mbx.keyRing.getPubCommKey()).toBe(pubCommKey);
    expect(mbx.keyRing.hpk).toEqual(hpk);

    const backup = await mbx.keyRing.backup();

    const restoredMbx = await Mailbox.fromBackup('from_backup', backup);
    if (!restoredMbx.keyRing) {
      throw new Error('no keyRing');
    }

    expect(restoredMbx.keyRing.getPubCommKey()).toBe(pubCommKey);
    expect(restoredMbx.keyRing.hpk).toEqual(hpk);
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

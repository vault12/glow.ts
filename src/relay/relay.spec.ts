import { Relay } from './relay';
import { NaCl } from '../nacl/nacl';
import { Mailbox } from '../mailbox/mailbox';

describe('Relay', () => {
  let testRelay: Relay;
  let Alice: Mailbox;
  let Bob: Mailbox;

  beforeAll(async () => {
    NaCl.setInstance();
    testRelay = new Relay('https://z2.vault12.com');
    Alice = await Mailbox.new('Alice');
    Bob = await Mailbox.new('Bob');
    const aliceKey = Alice.getPubCommKey();
    const bobKey = Bob.getPubCommKey();
    await Alice.keyRing.addGuest('Bob', bobKey);
    await Bob.keyRing.addGuest('Alice', aliceKey);
  });

  it('count Bob mailbox', async () => {
    await Bob.connectToRelay(testRelay);
    const count = await Bob.count(testRelay);
    expect(count).toBe(0);
  });
});

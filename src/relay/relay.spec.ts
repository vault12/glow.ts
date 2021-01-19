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
    if (!aliceKey || !bobKey) {
      throw new Error('error');
    }
    await Alice.keyRing?.addGuest('Bob', bobKey);
    await Bob.keyRing?.addGuest('Alice', aliceKey);
  });

  it('should init', async () => {
    await Alice.connectToRelay(testRelay);
    const token = await Alice.relaySend('Bob', 'message', testRelay);
    expect(token.length).toBeGreaterThan(0);
    const ttl = await testRelay.messageStatus(Alice, token);
    expect(ttl).toBeGreaterThan(0);
  });

  it('count Bob mailbox', async () => {
    const r = new Relay('https://z2.vault12.com');
    await Bob.connectToRelay(r);
    const count = await r.count(Bob);
    console.log(count);
  });
});

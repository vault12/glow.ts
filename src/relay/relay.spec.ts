import { Relay } from './relay';
import { NaCl } from '../nacl/nacl';
import { Mailbox } from '../mailbox/mailbox';

describe('Relay', () => {
  let testRelay: Relay;
  let Alice: Mailbox;
  let Bob: Mailbox;
  let nonce: string;

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

  it('send a message', async () => {
    await Alice.connectToRelay(testRelay);
    const stat = await Alice.relaySend('Bob', 'message', testRelay);
    expect(stat.token.length).toBeGreaterThan(0);
    nonce = stat.nonce;
    const ttl = await testRelay.messageStatus(Alice, stat.token);
    expect(ttl).toBeGreaterThan(0);
  });

  it('count Bob mailbox', async () => {
    await Bob.connectToRelay(testRelay);
    const count = await testRelay.count(Bob);
    expect(count).toBe(1);
  });

  it('download Bob mailbox', async () => {
    await Bob.connectToRelay(testRelay);
    const downloaded = await testRelay.download(Bob);
    const encodedMessage = downloaded[0];
    const msg = await Bob.decodeMessage('Alice', encodedMessage.nonce, encodedMessage.data);
    expect(msg).toBe('message');
  });

  it('delete from Bob mailbox', async () => {
    await testRelay.delete(Bob, []);
    const count = await testRelay.count(Bob);
    expect(count).toBe(1);
    const deletedResponse = await testRelay.delete(Bob, [ nonce ]);
    expect(deletedResponse).toBe(0);
    const countAfterDeleted = await testRelay.count(Bob);
    expect(countAfterDeleted).toBe(0);
  });
});

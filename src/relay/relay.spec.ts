import { Relay } from './relay';
import { NaCl } from '../nacl/nacl';
import { Mailbox } from '../mailbox/mailbox';

describe('Relay', () => {
  let testRelay: Relay;
  let Alice: Mailbox;
  let Bob: Mailbox;
  let nonce: string;
  let token: string;

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
    await Alice.keyRing.addGuest('Bob', bobKey);
    await Bob.keyRing.addGuest('Alice', aliceKey);
  });

  it('send a message', async () => {
    await Alice.connectToRelay(testRelay);
    const stat = await Alice.upload(testRelay, 'Bob', 'message');
    expect(stat.token.length).toBeGreaterThan(0);
    nonce = stat.nonce;
    token = stat.token;
    const ttl = await Alice.messageStatus(testRelay, token);
    expect(ttl).toBeGreaterThan(0);
  });

  it('count Bob mailbox', async () => {
    await Bob.connectToRelay(testRelay);
    const count = await Bob.count(testRelay);
    expect(count).toBe(1);
  });

  it('download Bob mailbox', async () => {
    await Bob.connectToRelay(testRelay);
    const downloaded = await Bob.download(testRelay);
    const encodedMessage = downloaded[0];
    const msg = await Bob.decodeMessage('Alice', encodedMessage.nonce, encodedMessage.data);
    expect(msg).toBe('message');
  });

  it('delete from Bob mailbox', async () => {
    await testRelay.runCmd('delete', Bob, { payload: [] });
    const count = await Bob.count(testRelay);
    expect(count).toBe(1);
    const deletedResponse = await testRelay.runCmd('delete', Bob, { payload: [ nonce ]});
    expect(deletedResponse).toBe(0);
    const countAfterDeleted = await Bob.count(testRelay);
    expect(countAfterDeleted).toBe(0);
  });

  it('check deleted message status', async () => {
    const ttl = await Alice.messageStatus(testRelay, token);
    expect(ttl).toBe(-2); // the key is missing on the relay
  });
});

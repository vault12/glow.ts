import { Relay } from '../relay/relay';
import { NaCl } from '../nacl/nacl';
import { Mailbox } from './mailbox';

describe('Mailbox / Messages', () => {
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

    await Alice.keyRing.addGuest('Bob', Bob.getPubCommKey());
    await Bob.keyRing.addGuest('Alice', Alice.getPubCommKey());

    await Alice.connectToRelay(testRelay);
    await Bob.connectToRelay(testRelay);
  });

  it('send a message', async () => {
    const wrongRecipient = Alice.upload(testRelay, 'Carl', 'some message');
    expect(wrongRecipient).rejects.toThrow(Error);

    const stat = await Alice.upload(testRelay, 'Bob', 'some message');
    expect(stat.token.length).toBeGreaterThan(0);
    nonce = stat.nonce;
    token = stat.token;
    const ttl = await Alice.messageStatus(testRelay, token);
    expect(ttl).toBeGreaterThan(0);
  });

  it('count Bob mailbox', async () => {
    const count = await Bob.count(testRelay);
    expect(count).toBe(1);
  });

  it('download Bob mailbox', async () => {
    const downloaded = await Bob.download(testRelay);
    const message = downloaded[0];
    expect(message.data).toBe('some message');
  });

  it('delete from Bob mailbox', async () => {
    await Bob.delete(testRelay, []);
    const count = await Bob.count(testRelay);
    expect(count).toBe(1);
    const deletedResponse = await Bob.delete(testRelay, [ nonce ]);
    expect(deletedResponse).toBe(0);
    const countAfterDeleted = await Bob.count(testRelay);
    expect(countAfterDeleted).toBe(0);
  });

  it('check deleted message status', async () => {
    const ttl = await Alice.messageStatus(testRelay, token);
    expect(ttl).toBe(0); // the key is missing on the relay
  });
});

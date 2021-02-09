import { NaCl } from '../nacl/nacl';
import { Mailbox } from './mailbox';
import { testRelayURL } from '../tests.helper';

describe('Mailbox / Messages', () => {
  let Alice: Mailbox;
  let Bob: Mailbox;
  let nonce: string;
  let token: string;

  beforeAll(async () => {
    NaCl.setInstance();

    Alice = await Mailbox.new('Alice');
    Bob = await Mailbox.new('Bob');

    await Alice.keyRing.addGuest('Bob', Bob.getPubCommKey());
    await Bob.keyRing.addGuest('Alice', Alice.getPubCommKey());

    await Alice.connectToRelay(testRelayURL);
    await Bob.connectToRelay(testRelayURL);
  });

  it('send a message', async () => {
    const wrongRecipient = Alice.upload(testRelayURL, 'Carl', 'some message');
    expect(wrongRecipient).rejects.toThrow(Error);

    token = await Alice.upload(testRelayURL, 'Bob', 'some message');
    expect(token.length).toBeGreaterThan(0);
    const ttl = await Alice.messageStatus(testRelayURL, token);
    expect(ttl).toBeGreaterThan(0);
  });

  it('count Bob mailbox', async () => {
    const count = await Bob.count(testRelayURL);
    expect(count).toBe(1);
  });

  it('download Bob mailbox', async () => {
    const downloaded = await Bob.download(testRelayURL);
    const message = downloaded[0];
    nonce = message.nonce;
    expect(message.data).toBe('some message');
  });

  it('delete from Bob mailbox', async () => {
    await Bob.delete(testRelayURL, []);
    const count = await Bob.count(testRelayURL);
    expect(count).toBe(1);
    const deletedResponse = await Bob.delete(testRelayURL, [ nonce ]);
    expect(deletedResponse).toBe(0);
    const countAfterDeleted = await Bob.count(testRelayURL);
    expect(countAfterDeleted).toBe(0);
  });

  it('check deleted message status', async () => {
    const ttl = await Alice.messageStatus(testRelayURL, token);
    expect(ttl).toBe(0); // the key is missing on the relay
  });

  it('send unencrypted message', async () => {
    const token = await Alice.upload(testRelayURL, 'Bob', 'some unencrypted message', false);
    expect(token.length).toBeGreaterThan(0);
    const count = await Bob.count(testRelayURL);
    expect(count).toBe(1);
    const [ message ] = await Bob.download(testRelayURL);
    expect(message.data).toBe('some unencrypted message');
  });
});

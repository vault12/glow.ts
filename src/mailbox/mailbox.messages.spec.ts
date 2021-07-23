import { NaCl } from '../nacl/nacl';
import { Mailbox } from './mailbox';
import { testRelayURL } from '../tests.helper';
import { MessageStatusResponse } from '../zax.interface';
import { CryptoStorage } from '../crypto-storage/crypto-storage';
import { config } from '../config';

describe('Mailbox / Messages', () => {
  let Alice: Mailbox;
  let Bob: Mailbox;
  let nonce: string;
  let token: string;

  beforeAll(() => {
    NaCl.setDefaultInstance();
    CryptoStorage.setDefaultStorageDriver();
  });

  beforeEach(async () => {
    Alice = await Mailbox.new('Alice');
    Bob = await Mailbox.new('Bob');

    await Alice.keyRing.addGuest('Bob', Bob.keyRing.getPubCommKey());
    await Bob.keyRing.addGuest('Alice', Alice.keyRing.getPubCommKey());
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
    expect(ttl).toBe(MessageStatusResponse.MissingKey); // the key is missing on the relay
  });

  it('should reconnect after token expiration timeout', async () => {
    // using 'modern' breaks the test in Jest 27+ environment
    // See https://jestjs.io/blog/2021/05/25/jest-27#flipping-defaults
    // TODO: fix this
    jest.useFakeTimers('legacy');
    await Bob.connectToRelay(testRelayURL);
    const connectSpy = jest.spyOn(Bob, 'connectToRelay');

    // fast-forward to where the token is not yet expired
    jest.advanceTimersByTime(config.RELAY_SESSION_TIMEOUT - 1);
    await Bob.download(testRelayURL);
    expect(connectSpy).not.toHaveBeenCalled();

    // has to reconnect under the hood when a token expires
    jest.advanceTimersByTime(2);
    await Bob.download(testRelayURL);
    expect(connectSpy).toHaveBeenCalledTimes(1);

    jest.clearAllTimers();
  });

});

import { NaCl } from '../nacl/nacl';
import { Mailbox } from './mailbox';
import { testRelayURL, testRelayURL2 } from '../tests.helper';
import { CryptoStorage } from '../crypto-storage/crypto-storage';

describe('Mailbox simultaneously', () => {
  let Alice: Mailbox;
  let Bob: Mailbox;
  const msg1 = 'hi';
  const msg2 = 'hi there';

  beforeAll(async () => {
    NaCl.setDefaultInstance();
    CryptoStorage.setDefaultStorageDriver();

  });

  describe('using different mailboxes simultaneously', () => {

    beforeAll(async () => {
      await createMailboxes();
    });

    it('send messages from different mailboxes', async() => {
      await Promise.all([
        Alice.upload(testRelayURL, 'Bob', msg1),
        Alice.upload(testRelayURL, 'Bob', msg2),
        Bob.upload(testRelayURL, 'Alice', msg2)
      ]);
    });

    it('receive messages', async() => {
      const [aliceMsgs, bobMsgs] = await Promise.all([
        Alice.download(testRelayURL),
        Bob.download(testRelayURL)
      ]);
      expect(aliceMsgs.map(m => m.data)).toEqual([msg2]);
      expect(bobMsgs.map(m => m.data).sort()).toEqual([msg1, msg2].sort());
      await Promise.all([
        Alice.delete(testRelayURL, aliceMsgs.map(m => m.nonce)),
        Bob.delete(testRelayURL, bobMsgs.map(m => m.nonce))
      ]);
    });
  });

  describe('using different relays simultaneously', () => {

    beforeAll(async () => {
      await createMailboxes();
    });

    it('send messages', async () => {
      await Promise.all([
        Alice.upload(testRelayURL, 'Bob', msg1),
        Alice.upload(testRelayURL2, 'Bob', msg1),
        Alice.upload(testRelayURL2, 'Bob', msg2),
      ]);
    });

    it('receive messages', async () => {
      const [msgsRelay1, msgsRelay2] = await Promise.all([
        Bob.download(testRelayURL),
        Bob.download(testRelayURL2),
      ]);
      expect(msgsRelay1.map(m => m.data)).toEqual([msg1]);
      expect(msgsRelay2.map(m => m.data).sort()).toEqual([msg1, msg2].sort());
      Bob.delete(testRelayURL, msgsRelay1.map(m => m.nonce));
      Bob.delete(testRelayURL2, msgsRelay2.map(m => m.nonce));
    });
  });


  async function createMailboxes() {

    Alice = await Mailbox.new('Alice');
    Bob = await Mailbox.new('Bob');

    await Alice.keyRing.addGuest('Bob', Bob.keyRing.getPubCommKey());
    await Bob.keyRing.addGuest('Alice', Alice.keyRing.getPubCommKey());
  }

});
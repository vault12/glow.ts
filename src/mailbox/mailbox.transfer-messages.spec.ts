import { CryptoStorage } from '../crypto-storage/crypto-storage';
import { InMemoryStorage } from '../crypto-storage/in-memory-storage';
import { NaCl } from '../nacl/nacl';
import { testRelayURL } from '../tests.helper';
import { Mailbox } from './mailbox';


describe('Mailbox / Transfer Messages', () => {

  let Alice: Mailbox;
  let Bob: Mailbox;
  const messages = [
    JSON.stringify({object: 'message'}),
    'some unencrypted message',
    'special ;@@#2sd characters',
    'кирилиця'
  ];
  const encryptMessages = [true, false];
  const storage = new InMemoryStorage();

  beforeAll(() => {
    NaCl.setDefaultInstance();
    CryptoStorage.setStorageDriver(storage);
  });

  encryptMessages.forEach(encrypt => {
    messages.forEach((msg) => {
      describe(`transfer message ${JSON.stringify(msg)} ${(encrypt ? 'with' : 'without')} encryption`, () => {
        beforeAll(async () => {
          storage.reset();
          Alice = await Mailbox.new('Alice');
          Bob = await Mailbox.new('Bob');

          await Alice.keyRing.addGuest('Bob', Bob.keyRing.getPubCommKey());
          await Bob.keyRing.addGuest('Alice', Alice.keyRing.getPubCommKey());
        });

        it('upload', async () => {
          const token = await Alice.upload(testRelayURL, 'Bob', msg, encrypt);
          expect(token.length).toBeGreaterThan(0);
        });

        it('download', async () => {
          const [ message ] = await Bob.download(testRelayURL);
          expect(message.data).toEqual(msg);
          Bob.delete(testRelayURL, [message.nonce]);
        });
      });
    });
  });

});
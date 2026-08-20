import { CryptoStorage } from '../crypto-storage/crypto-storage';
import { InMemoryStorage } from '../crypto-storage/in-memory-storage';
import { NaCl } from '../nacl/nacl';
import { Utils } from '../utils/utils';
import { ZaxMessageKind, ZaxRawMessage } from '../zax.interface';
import { Mailbox } from './mailbox';

/**
 * Offline tests of message authenticity classification.
 * A payload that fails authenticated decryption must never surface as an
 * authenticated `message` — regardless of whether it was sent as plaintext,
 * forged by a malicious relay, or tampered with in transit.
 */
describe('Mailbox / Message authenticity', () => {
  let Alice: Mailbox;
  let Bob: Mailbox;
  let Mallory: Mailbox;
  let aliceHpk: string;

  const rawMessage = (data: string, nonce: string): ZaxRawMessage => ({
    data,
    time: Date.now(),
    from: aliceHpk,
    nonce,
    kind: ZaxMessageKind.message
  });

  beforeAll(async () => {
    NaCl.setDefaultInstance();
    CryptoStorage.setStorageDriver(new InMemoryStorage());

    Alice = await Mailbox.new('Alice');
    Bob = await Mailbox.new('Bob');
    Mallory = await Mailbox.new('Mallory');

    await Alice.keyRing.addGuest('Bob', Bob.keyRing.getPubCommKey());
    await Bob.keyRing.addGuest('Alice', Alice.keyRing.getPubCommKey());
    // Mallory knows Bob's public key, but Bob's keyring has no entry for Mallory
    await Mallory.keyRing.addGuest('Bob', Bob.keyRing.getPubCommKey());

    aliceHpk = await Alice.keyRing.getHpk();
  });

  it('classifies a genuine encrypted message as an authenticated `message`', async () => {
    const { nonce, ctext } = await Alice.encodeMessage('Bob', 'hello Bob');
    const parsed = await Bob['parseTextMessage'](rawMessage(ctext, nonce), 'Alice');

    expect(parsed.kind).toBe(ZaxMessageKind.message);
    expect(parsed.data).toBe('hello Bob');
    expect(parsed.senderTag).toBe('Alice');
  });

  it('labels a plaintext payload as `unverified`, never as an authenticated `message`', async () => {
    const plaintext = 'some unencrypted message';
    const nonce = Utils.toBase64(await NaCl.getInstance().crypto_box_random_nonce());
    const parsed = await Bob['parseTextMessage'](rawMessage(plaintext, nonce), 'Alice');

    expect(parsed.kind).toBe(ZaxMessageKind.unverified);
    // the raw payload is passed through untouched for the application to judge
    expect(parsed.data).toBe(plaintext);
    expect(parsed.senderTag).toBe('Alice');
    if (parsed.kind === ZaxMessageKind.unverified) {
      expect(parsed.from).toBe(aliceHpk);
    }
  });

  it('labels a forged ciphertext from a wrong key as `unverified`', async () => {
    // Mallory encrypts a valid ciphertext to Bob, and a malicious relay attributes
    // it to Alice: authentication with Alice's key must fail
    const { nonce, ctext } = await Mallory.encodeMessage('Bob', 'forged message');
    const parsed = await Bob['parseTextMessage'](rawMessage(ctext, nonce), 'Alice');

    expect(parsed.kind).toBe(ZaxMessageKind.unverified);
    expect(parsed.data).toBe(ctext);
    expect(parsed.senderTag).toBe('Alice');
  });

  it('labels a tampered genuine ciphertext as `unverified`', async () => {
    const { nonce, ctext } = await Alice.encodeMessage('Bob', 'hello Bob');
    const corrupted = Utils.fromBase64(ctext);
    corrupted[0] ^= 0xFF;
    const tampered = Utils.toBase64(corrupted);
    const parsed = await Bob['parseTextMessage'](rawMessage(tampered, nonce), 'Alice');

    expect(parsed.kind).toBe(ZaxMessageKind.unverified);
    expect(parsed.data).toBe(tampered);
  });
});

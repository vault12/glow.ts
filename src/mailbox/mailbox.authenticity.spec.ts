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

  const rawMessage = (data: string, nonce: string,
    kind: ZaxMessageKind = ZaxMessageKind.message): ZaxRawMessage => ({
    data,
    time: Date.now(),
    from: aliceHpk,
    nonce,
    kind
  } as ZaxRawMessage);

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

  it('labels a message with a wrong-length nonce as `unverified` instead of failing the batch', async () => {
    // `crypto_box_open` throws on a nonce that is not exactly `crypto_box_NONCEBYTES` long,
    // which would reject the whole `download` and drop every other message in it
    const { ctext } = await Alice.encodeMessage('Bob', 'hello Bob');
    const shortNonce = Utils.toBase64(await NaCl.getInstance().random_bytes(8));
    const parsed = await Bob['parseTextMessage'](rawMessage(ctext, shortNonce), 'Alice');

    expect(parsed.kind).toBe(ZaxMessageKind.unverified);
    expect(parsed.data).toBe(ctext);
  });

  it('labels a message with a non-base64 nonce as `unverified`', async () => {
    const { ctext } = await Alice.encodeMessage('Bob', 'hello Bob');
    const parsed = await Bob['parseTextMessage'](rawMessage(ctext, '!!! not base64 !!!'), 'Alice');

    expect(parsed.kind).toBe(ZaxMessageKind.unverified);
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

  it('labels an authenticated payload of invalid UTF-8 as `unverified` instead of failing the batch', async () => {
    // a raw `crypto_box` (bypassing encodeMessage's UTF-8 encoding) authenticates fine,
    // but `decode_utf8` throws on the decrypted bytes — which would reject the whole `download`
    const nacl = NaCl.getInstance();
    const nonce = await nacl.crypto_box_random_nonce();
    const ctext = await nacl.crypto_box(new Uint8Array([0xC3]), nonce,
      Utils.fromBase64(Bob.keyRing.getPubCommKey()), Utils.fromBase64(Alice.keyRing.getPrivateCommKey()));
    const parsed = await Bob['parseTextMessage'](
      rawMessage(Utils.toBase64(ctext), Utils.toBase64(nonce)), 'Alice');

    expect(parsed.kind).toBe(ZaxMessageKind.unverified);
  });

  // ---------- `file` messages and unknown kinds ----------

  const metadata = { name: 'report.pdf', orig_size: 1024, md5: 'd41d8cd98f00b204e9800998ecf8427e' };

  const fileEnvelope = (nonce: string, ctext: string): string =>
    JSON.stringify({ nonce, ctext, uploadID: 'upload-1' });

  it('classifies a genuine file message as an authenticated `file`', async () => {
    const { nonce, ctext } = await Alice.encodeMessage('Bob', JSON.stringify(metadata));
    const raw = rawMessage(fileEnvelope(nonce, ctext), nonce, ZaxMessageKind.file);
    const parsed = await Bob['parseFileMessage'](raw, 'Alice');

    expect(parsed.kind).toBe(ZaxMessageKind.file);
    if (parsed.kind === ZaxMessageKind.file) {
      expect(parsed.data).toEqual(metadata);
      expect(parsed.uploadID).toBe('upload-1');
    }
  });

  it('labels a file message with a garbage envelope as `unverified` instead of failing the batch', async () => {
    // `JSON.parse` on the envelope throws, which would reject the whole `download`
    const nonce = Utils.toBase64(await NaCl.getInstance().crypto_box_random_nonce());
    const raw = rawMessage('not a JSON envelope', nonce, ZaxMessageKind.file);
    const parsed = await Bob['parseFileMessage'](raw, 'Alice');

    expect(parsed.kind).toBe(ZaxMessageKind.unverified);
    expect(parsed.data).toBe('not a JSON envelope');
  });

  it('labels a file message encrypted with a wrong key as `unverified`', async () => {
    const { nonce, ctext } = await Mallory.encodeMessage('Bob', JSON.stringify(metadata));
    const raw = rawMessage(fileEnvelope(nonce, ctext), nonce, ZaxMessageKind.file);
    const parsed = await Bob['parseFileMessage'](raw, 'Alice');

    expect(parsed.kind).toBe(ZaxMessageKind.unverified);
  });

  it('labels an authenticated file message with malformed metadata as `unverified`', async () => {
    // authentication passed, but the decrypted metadata is not valid JSON:
    // a sender in the keyring must not be able to reject the whole batch either
    const { nonce, ctext } = await Alice.encodeMessage('Bob', 'not JSON metadata');
    const raw = rawMessage(fileEnvelope(nonce, ctext), nonce, ZaxMessageKind.file);
    const parsed = await Bob['parseFileMessage'](raw, 'Alice');

    expect(parsed.kind).toBe(ZaxMessageKind.unverified);
  });

  it('labels a file message with a malformed envelope (no uploadID) as `unverified`', async () => {
    const { nonce, ctext } = await Alice.encodeMessage('Bob', JSON.stringify(metadata));
    const raw = rawMessage(JSON.stringify({ nonce, ctext }), nonce, ZaxMessageKind.file);
    const parsed = await Bob['parseFileMessage'](raw, 'Alice');

    expect(parsed.kind).toBe(ZaxMessageKind.unverified);
  });

  it('labels authenticated file metadata of the wrong JSON shape as `unverified`', async () => {
    // JSON.parse accepts any JSON value; only an object with the mandatory fields is metadata
    for (const payload of ['null', '42', '[]', '{}', '{"name":"a.txt"}']) {
      const { nonce, ctext } = await Alice.encodeMessage('Bob', payload);
      const raw = rawMessage(fileEnvelope(nonce, ctext), nonce, ZaxMessageKind.file);
      const parsed = await Bob['parseFileMessage'](raw, 'Alice');

      expect(parsed.kind).toBe(ZaxMessageKind.unverified);
    }
  });

  it('labels a message with an unknown `kind` as `unverified` instead of failing the batch', async () => {
    // `kind` is supplied by the relay and may hold an arbitrary value at runtime
    const { nonce, ctext } = await Alice.encodeMessage('Bob', 'hello Bob');
    const raw = rawMessage(ctext, nonce, 'sticker' as ZaxMessageKind);
    const parsed = await Bob['parseMessage'](raw);

    expect(parsed.kind).toBe(ZaxMessageKind.unverified);
    if (parsed.kind === ZaxMessageKind.unverified) {
      expect(parsed.senderTag).toBe('Alice');
      expect(parsed.data).toBe(ctext);
    }
  });
});

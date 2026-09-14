import { NaCl } from '../nacl/nacl';
import { NaClDriver, EncryptedMessage } from '../nacl/nacl-driver.interface';
import { EncryptionHelper } from '../nacl/encryption.helper';
import { KeyRing } from '../keyring/keyring';
import { Base64, Utils } from '../utils/utils';
import { Relay, RelayConnectionData } from '../relay/relay';
import {
  RelayCommand,
  StartFileUploadResponse,
  UploadFileChunkResponse,
  FileStatusResponse,
  DeleteFileResponse,
  MessageStatusResponse,
  FileUploadMetadata,
  ZaxMessageKind,
  ZaxRawMessage,
  ZaxFileMessage,
  ZaxPlainMessage,
  ZaxTextMessage,
  ZaxUnverifiedMessage,
  ZaxParsedMessage
} from '../zax.interface';
import { RelayFactory } from '../relay/relay-factory';
import { Mutex } from 'async-mutex';


/**
 * Mailbox class represents a wrapper around a Keyring that allows to exchange
 * encrypted messages with other Mailboxes via a relay
 */
export class Mailbox {
  public keyRing: KeyRing;
  public identity: string;
  /**
   * each mailbox use it's own relays for connection
   * this gives possibility to connect different mailboxes to same server simultaneously
   * because they will use different session keys, tokens, server pub keys
   */

  private relayFactory = new RelayFactory;

  private relayConnectionMutexes = new Map<string, Mutex>();

  private nacl: NaClDriver;

  private constructor(naclDriver: NaClDriver, keyRing: KeyRing, identity: string) {
    this.nacl = naclDriver;
    this.keyRing = keyRing;
    this.identity = identity;
  }

  static async new(identity: string): Promise<Mailbox> {
    return new Mailbox(NaCl.getInstance(), await KeyRing.new(identity), identity);
  }

  // ---------- Alternative initializers ----------

  /**
   * Create a Mailbox where the secret identity key is derived from a well-known seed
   */
  static async fromSeed(id: string, seed: Uint8Array | string): Promise<Mailbox> {
    const mbx = await this.new(id);
    if (!(seed instanceof Uint8Array)) {
      seed = Utils.encode_latin1(seed);
    }
    await mbx.keyRing.setCommFromSeed(seed);
    return mbx;
  }

  /**
   * Create a Mailbox from the known secret identity key
   */
  static async fromSecKey(id: string, rawSecretKey: Uint8Array | Base64): Promise<Mailbox> {
    const mbx = await this.new(id);
    if (!(rawSecretKey instanceof Uint8Array)) {
      rawSecretKey = Utils.fromBase64(rawSecretKey);
    }
    await mbx.keyRing.setCommFromSecKey(rawSecretKey);
    return mbx;
  }

  /**
   * Create a Mailbox from the backup string
   */
  static async fromBackup(identity: string, backup: string): Promise<Mailbox> {
    return new Mailbox(NaCl.getInstance(), await KeyRing.fromBackup(identity, backup), identity);
  }

  // ---------- Relay message commands (public API) ----------

  /**
   * Sends a free-form object to a guest we already have in our keyring. Set `encrypt` to `false` to
   * send a plaintext message. Returns a token that can be used with `messageStatus` command to check
   * the status of the message.
   *
   * WARNING: a plaintext message (`encrypt = false`) has no confidentiality and no authenticity:
   * on receipt it is indistinguishable from a message forged by the relay. `download` never
   * returns it as an authenticated `message`: it is classified as `ZaxMessageKind.unverified` if
   * the recipient already has the sender's key in their keyring, or as `ZaxMessageKind.plain` if
   * they do not. Only use plaintext for bootstrap flows where the recipient does not have the
   * sender's key yet, and never trust its content
   */
  async upload(url: string, guestKey: string, message: string, encrypt = true): Promise<Base64> {
    const relay = await this.prepareRelay(url);
    const guestPk = this.getGuestKey(guestKey);
    const payload = encrypt ? await this.encodeMessage(guestKey, message) : message;
    const toHpk = Utils.toBase64(await this.nacl.h2(Utils.fromBase64(guestPk)));

    const [token] = await this.runRelayCommand(relay, RelayCommand.upload, { to: toHpk, payload });
    return token;
  }

  /**
   * Downloads all messages from a relay, decrypts them with a relay key,
   * and then parses each message to find out if it's an authenticated text message (`message`),
   * a file message (`file`), a message from a sender whose HPK is missing in the keyring
   * (`plain`), or a message claiming to be from a known sender whose payload failed
   * authenticated decryption (`unverified`). Returns an array of mixed messages.
   *
   * A single malformed message — text or file — never rejects the batch: when its sender
   * is in the keyring it is returned as `unverified` alongside the messages that did parse
   * (an unknown sender's payload is returned as `plain` in any case), and the same applies
   * to a message with an unknown `kind`, which an untrusted relay may set to an arbitrary value
   */
  async download(url: string) {
    const relay = await this.prepareRelay(url);
    const response = await this.runRelayCommand(relay, RelayCommand.download);
    const messages: ZaxRawMessage[] = await this.decryptResponse<ZaxRawMessage[]>(relay, response);

    const parsedMessages: ZaxParsedMessage[] = [];
    for (const message of messages) {
      parsedMessages.push(await this.parseMessage(message));
    }
    return parsedMessages;
  }

  /**
   * Classifies a single raw relay message by sender and `kind`
   */
  private async parseMessage(message: ZaxRawMessage): Promise<ZaxParsedMessage> {
    const senderTag = this.keyRing.getTagByHpk(message.from);
    if (!senderTag) {
      return await this.parsePlainMessage(message);
    }
    try {
      if (message.kind === 'message') {
        return await this.parseTextMessage(message, senderTag);
      } else if (message.kind === 'file') {
        return await this.parseFileMessage(message, senderTag);
      }
    } catch {
      // no single message may reject the whole batch, whatever a parser throws
    }
    // a parser failure above, or an unknown `kind` (the relay may put anything there)
    return this.markUnverified(message, senderTag);
  }

  /**
   * Marks a raw Zax message as one that can't be decrypted,
   * because sender's HPK is not found in the keyring
   */
  private async parsePlainMessage({ data, time, from, nonce }: ZaxRawMessage) {
    return { data, time, from, nonce, kind: ZaxMessageKind.plain } as ZaxPlainMessage;
  }

  /**
   * Marks a raw Zax message claiming to be from a known sender as one that failed
   * authentication, passing the relay-supplied payload through untouched
   */
  private markUnverified(message: ZaxRawMessage, senderTag: string): ZaxUnverifiedMessage {
    return { data: message.data, time: message.time, senderTag, from: message.from,
      nonce: message.nonce, kind: ZaxMessageKind.unverified };
  }

  /**
   * Decrypts a message that represents uploaded file metadata. A payload that can not be
   * authenticated (a garbage envelope, a forged ciphertext, or malformed metadata)
   * is returned as `ZaxMessageKind.unverified` with the raw relay-supplied bytes.
   *
   * Unlike text messages, file metadata is always encrypted on upload (`startFileUpload`
   * has no plaintext option), so an `unverified` file message always indicates forgery,
   * tampering, or corruption — never a legitimate plaintext upload
   */
  private async parseFileMessage(message: ZaxRawMessage,
    senderTag: string): Promise<ZaxFileMessage | ZaxUnverifiedMessage> {
    try {
      const { nonce, ctext, uploadID } = JSON.parse(message.data);
      if (typeof nonce !== 'string' || typeof ctext !== 'string' || typeof uploadID !== 'string') {
        return this.markUnverified(message, senderTag);
      }
      const rawData = await this.decodeMessage(senderTag, nonce, ctext);
      if (rawData === null) {
        return this.markUnverified(message, senderTag);
      }
      const data: unknown = JSON.parse(rawData);
      if (!Mailbox.isFileMetadata(data)) {
        return this.markUnverified(message, senderTag);
      }
      return { data, time: message.time, senderTag, uploadID, nonce, kind: ZaxMessageKind.file };
    } catch {
      // the envelope or the authenticated metadata inside it is not valid JSON
      return this.markUnverified(message, senderTag);
    }
  }

  /**
   * Runtime check of decrypted file metadata: `JSON.parse` alone accepts any JSON value
   * (`null`, `42`, `[]`), so require an object carrying the mandatory fields
   */
  private static isFileMetadata(data: unknown): data is FileUploadMetadata {
    return typeof data === 'object' && data !== null && !Array.isArray(data) &&
      typeof (data as FileUploadMetadata).name === 'string' &&
      typeof (data as FileUploadMetadata).orig_size === 'number';
  }

  /**
   * Attempts authenticated decryption of a regular Zax message. A payload that can not be
   * authenticated with the sender's key (a plaintext upload, a forged message, or a tampered
   * ciphertext — indistinguishable cases on receipt) is returned as `ZaxMessageKind.unverified`
   * with the raw relay-supplied bytes, so that the application can decide whether to trust it
   */
  private async parseTextMessage(message: ZaxRawMessage,
    senderTag: string): Promise<ZaxTextMessage | ZaxUnverifiedMessage> {
    const data = await this.decodeMessage(senderTag, message.nonce, message.data);
    if (data === null) {
      return this.markUnverified(message, senderTag);
    }
    return ({ data, time: message.time, senderTag, nonce: message.nonce, kind: ZaxMessageKind.message });
  }

  /**
   * Returns the number of messages in the mailbox on a given relay
   */
  async count(url: string): Promise<number> {
    const relay = await this.prepareRelay(url);
    const response = await this.runRelayCommand(relay, RelayCommand.count);
    return await this.decryptResponse(relay, response);
  }

  /**
  * Deletes messages from a relay given a list of base64 message nonces,
  * and returns the number of remaining messages
  */
  async delete(url: string, nonceList: Base64[]): Promise<number> {
    const relay = await this.prepareRelay(url);
    const [response] = await this.runRelayCommand(relay, RelayCommand.delete, { payload: nonceList });
    return parseInt(response, 10);
  }

  /**
  * Gets the status of a previously sent Zax message by a storage token.
  * Returns "time to live" in seconds or a negative value if it's not applicable.
  * See `MessageStatusResponse` values for reference
  */
  async messageStatus(url: string, storageToken: Base64): Promise<MessageStatusResponse | number> {
    const relay = await this.prepareRelay(url);
    const [response] = await this.runRelayCommand(relay, RelayCommand.messageStatus, { token: storageToken });
    const status = parseInt(response, 10);
    return status;
  }

  // ---------- Relay file commands (public API) ----------

  /**
   * Asks Zax to start a new upload session, and returns a unique file identifier
   * required to upload file chunks.
   */
  async startFileUpload(url: string, guest: string,
    rawMetadata: FileUploadMetadata): Promise<StartFileUploadResponse> {
    const relay = await this.prepareRelay(url);
    const guestPk = this.getGuestKey(guest);
    const toHpk = Utils.toBase64(await this.nacl.h2(Utils.fromBase64(guestPk)));

    const secretKey = await this.nacl.random_bytes(this.nacl.crypto_secretbox_KEYBYTES);
    rawMetadata.skey = Utils.toBase64(secretKey);

    const metadata = await this.encodeMessage(guest, JSON.stringify(rawMetadata));

    const response = await this.runRelayCommand(relay, RelayCommand.startFileUpload, {
      to: toHpk,
      file_size: rawMetadata.orig_size,
      metadata
    });

    const decrypted = await this.decryptResponse<StartFileUploadResponse>(relay, response);
    // append symmetric secret key (unique for this upload session) to the server response
    decrypted.skey = secretKey;
    return decrypted;
  }

  /**
   * Encrypts the file chunk symmetrically and transfers it to a relay.
   * The chunk must not exceed `max_chunk_size` returned by `startFileUpload`.
   */
  async uploadFileChunk(url: string, uploadID: string, chunk: Uint8Array,
    part: number, totalParts: number, skey: Uint8Array): Promise<UploadFileChunkResponse> {
    const relay = await this.prepareRelay(url);
    const encodedChunk = await EncryptionHelper.encodeMessageSymmetric(chunk, skey);
    const response = await this.runRelayCommand(relay, RelayCommand.uploadFileChunk, {
      uploadID,
      part,
      last_chunk: (totalParts - 1 === part), // marker of the last chunk, sent only once
      nonce: encodedChunk.nonce
    }, encodedChunk.ctext); // do not encode file chunk contents, as it's already encoded with symmetric encryption
    return await this.decryptResponse(relay, response);
  }

  /**
   * Returns the status of a file upload by its relay-specific uploadID. Uploader can call it
   * to verify the correct transfer, and downloader can check if the file exists and retrieve
   * the number of chunks
   */
  async getFileStatus(url: string, uploadID: string): Promise<FileStatusResponse> {
    const relay = await this.prepareRelay(url);
    const response = await this.runRelayCommand(relay, RelayCommand.fileStatus, { uploadID });
    return await this.decryptResponse(relay, response);
  }

  /**
   * Fetches the file metadata by uploadID, which was declared by the uploader
   */
  async getFileMetadata(url: string, uploadID: string): Promise<FileUploadMetadata> {
    const messages = await this.download(url);

    const fileMessage = messages
      .filter(message => message.kind === 'file')
      .find(message => (message as ZaxFileMessage).uploadID === uploadID);
    return fileMessage?.data as FileUploadMetadata;
  }

  /**
   * Downloads a binary chunk of a file from a relay by a given uploadID. The total number of chunks
   * can be retrieved via a `getFileStatus` request
   */
  async downloadFileChunk(url: string, uploadID: string, part: number, skey: Uint8Array | Base64):
    Promise<Uint8Array | null> {
    if (!(skey instanceof Uint8Array)) {
      skey = Utils.fromBase64(skey);
    }
    const relay = await this.prepareRelay(url);
    const response = await this.runRelayCommand(relay, RelayCommand.downloadFileChunk, { uploadID, part });
    const [nonce, ctext, fileCtext] = response;
    const decoded = await relay.decodeMessage<{nonce: string}>(nonce, ctext);
    return await EncryptionHelper.decodeMessageSymmetric(decoded.nonce, fileCtext, skey);
  }

  /**
   * Deletes a file from the relay (or all chunks uploaded so far, if the upload was not completed).
   * Can be called by either the sender or recipient
   */
  async deleteFile(url: string, uploadID: string): Promise<DeleteFileResponse> {
    const relay = await this.prepareRelay(url);
    const response = await this.runRelayCommand(relay, RelayCommand.deleteFile, { uploadID });
    return await this.decryptResponse(relay, response);
  }

  // ---------- Dealing with Relay ----------

  /**
   * Establishes a session, exchanges temp keys and proves our ownership of this
   * Mailbox to this specific relay. This is the first function to start
   * communications with any relay. Returns the number of messages in the mailbox
   */
  async connectToRelay(url: string): Promise<number> {
    const relay = this.relayFactory.getInstance(url);
    const connectionData = await relay.openConnection();
    const encryptedSignature = await this.encryptSignature(connectionData);

    const messagesNumber = await relay.prove(await relay.encodeMessage(JSON.stringify({
      pub_key: this.keyRing.getPubCommKey(),
      nonce: encryptedSignature.nonce,
      ctext: encryptedSignature.ctext
    })));
    return parseInt(messagesNumber, 10);
  }

  clearSession(url: string) {
    const relay = this.relayFactory.getInstance(url);
    relay.clearToken();
    relay.clearSession();
  }

  private async encryptSignature(connection: RelayConnectionData) {
    const privateKey = Utils.fromBase64(this.keyRing.getPrivateCommKey());
    return await EncryptionHelper.encodeMessage(connection.h2Signature, connection.relayPublicKey, privateKey);
  }

  /**
   * Gets a singleton Relay instance, and reconnects to a relay if a previous token has expired
   */
  private async prepareRelay(url: string): Promise<Relay> {
    const relay = this.relayFactory.getInstance(url);
    /**
     * allow establishing only once connection for pair mailbox-relay
     */
    await this.getRelayConnectionMutex(url).runExclusive(async () => {
      if (!relay.isConnected) {
        await this.connectToRelay(url);
      }
    });
    return relay;
  }

  /**
   * Encrypts the payload of the command and sends it to a relay
   */
  private async runRelayCommand(
    relay: Relay, command: RelayCommand, params?: {[key:string]: unknown}, ctext?: string): Promise<string[]> {
    params = { cmd: command, ...params };
    const hpk = await this.keyRing.getHpk();
    const message = await relay.encodeMessage(JSON.stringify(params));
    return await relay.runCmd(command, hpk, message, ctext);
  }

  /**
   * Parses relay's response to a command, for those commands that expect an encrypted message in return.
   * Two lines of POST response will be nonce and ctext
   */
  private async decryptResponse<T>(relay: Relay, response: string[]) {
    const [nonce, ctext] = response;
    return await relay.decodeMessage<T>(nonce, ctext);
  }

  // ---------- Message encoding / decoding ----------

  /**
   * Encodes `message` to the guest key of a guest already
   * added to the keyring
   */
  async encodeMessage(guest: string, message: string): Promise<EncryptedMessage> {
    const guestPk = this.getGuestKey(guest);
    const privateKey = this.keyRing.getPrivateCommKey();

    return await EncryptionHelper.encodeMessage(
      await this.nacl.encode_utf8(message), Utils.fromBase64(guestPk), Utils.fromBase64(privateKey));
  }

  /**
   * Decodes a ciphertext from a guest key already in our keyring with this nonce
   * @returns null if the payload could not be authenticated and decrypted with this guest's key.
   * A `null` carries no information about why: the payload may have been sent as plaintext,
   * forged, or tampered with — these cases can not be told apart on the receiving side
   */
  async decodeMessage(guest: string, nonce: Base64, ctext: Base64) {
    const guestPk = this.getGuestKey(guest);
    const privateKey = this.keyRing.getPrivateCommKey();
    let uint8ArrayNonce: Uint8Array;
    let uint8ArrayCtext: Uint8Array;
    try {
      // both values come from the relay and may be arbitrary bytes
      uint8ArrayNonce = Utils.fromBase64(nonce);
      uint8ArrayCtext = Utils.fromBase64(ctext);
    } catch {
      // not base64 — cannot be a nonce or ciphertext produced by `encodeMessage`
      return null;
    }
    // `crypto_box_open` throws on a nonce of the wrong length, so reject it here instead
    if (uint8ArrayNonce.length !== this.nacl.crypto_box_NONCEBYTES) {
      return null;
    }

    try {
      return await EncryptionHelper.decodeMessage(uint8ArrayNonce, uint8ArrayCtext,
        Utils.fromBase64(guestPk), Utils.fromBase64(privateKey));
    } catch {
      // `decode_utf8` throws on an authenticated payload that is not valid UTF-8
      return null;
    }
  }

  /**
   * Wrapper around `keyring.getGuestKey` that handles unknown guests
   */
  private getGuestKey(guest: string): string {
    const guestPk = this.keyRing.getGuestKey(guest);
    if (!guestPk) {
      throw new Error(`[Mailbox] Unknown guest ${guest}`);
    }
    return guestPk;
  }

  // ---------- Destroying Mailbox ----------

  /**
   * Deletes a Mailbox and all its data from local CryptoStorage. This is a very
   * destructive operation, use with caution - it will delete the Mailbox
   * keyring along with all stored public keys. To restore that information, you
   * will need to do another key exchange with all the guests on your keyring.
   */
  async selfDestruct() {
    await this.keyRing.selfDestruct();
  }

  private getRelayConnectionMutex(url: string) {
    if (!this.relayConnectionMutexes.has(url)) {
      this.relayConnectionMutexes.set(url, new Mutex());
    }
    return this.relayConnectionMutexes.get(url) as Mutex;
  }
}

import { NaCl } from '../nacl/nacl';
import { NaClDriver, EncryptedMessage } from '../nacl/nacl-driver.interface';
import { KeyRing } from '../keyring/keyring';
import { Base64, Utils } from '../utils/utils';
import { Relay, ConnectionData } from '../relay/relay';
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
  ZaxParsedMessage
} from '../zax.interface';

/**
 * Mailbox class represents a wrapper around a Keyring that allows to exchange
 * encrypted messages with other Mailboxes via a relay
 */
export class Mailbox {
  public keyRing: KeyRing;
  public identity: string;

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
  static async fromSeed(id: string, seed: Uint8Array): Promise<Mailbox> {
    const mbx = await this.new(id);
    await mbx.keyRing.setCommFromSeed(seed);
    return mbx;
  }

  /**
   * Create a Mailbox from the known secret identity key
   */
  static async fromSecKey(id: string, rawSecretKey: Uint8Array): Promise<Mailbox> {
    const mbx = await this.new(id);
    await mbx.keyRing.setCommFromSecKey(rawSecretKey);
    return mbx;
  }

  /**
   * Create a Mailbox from the backup string
   */
  static async fromBackup(identity: string, backup: string): Promise<Mailbox> {
    return new Mailbox(NaCl.getInstance(), await KeyRing.fromBackup(identity, backup), identity);
  }

  // ---------- Mailbox keys ----------

  /**
   * Returns HPK (hash of the public key) of the mailbox. This is what Zax relays
   * uses as the universal address of the mailbox
   */
  async getHpk(): Promise<Base64> {
    return await this.keyRing.getHpk();
  }

  /**
   * Returns public identity, which is the default communication key.
   * Correspondents can know it, whereas Relays do not need it (other than
   * temporarily for internal use during the ownership proof)
   */
  getPubCommKey(): string {
    return this.keyRing.getPubCommKey();
  }

  /**
   * Establishes a session, exchanges temp keys and proves our ownership of this
   * Mailbox to this specific relay. This is the first function to start
   * communications with any relay. Returns the number of messages in the mailbox
   */
  async connectToRelay(url: string): Promise<number> {
    const relay = await Relay.getInstance(url);
    const connectionData = await relay.openConnection();
    const encryptedSignature = await this.encryptSignature(connectionData);

    const messagesNumber = await relay.prove(await relay.encodeMessage({
      pub_key: this.keyRing.getPubCommKey(),
      nonce: encryptedSignature.nonce,
      ctext: encryptedSignature.ctext
    }));
    return parseInt(messagesNumber, 10);
  }

  private async encryptSignature(connectionData: ConnectionData) {
    const privateKey = Utils.fromBase64(this.keyRing.getPrivateCommKey());
    return await NaCl.rawEncodeMessage(connectionData.h2Signature, connectionData.relayPublicKey, privateKey);
  }

  // ---------- Relay message commands (public API) ----------

  /**
   * Sends a free-form object to a guest we already have in our keyring. Set `encrypt` to `false` to
   * send a plaintext message. Returns a token that can be used with `messageStatus` command to check
   * the status of the message
   */
  async upload(url: string, guestKey: string, message: any, encrypt = true): Promise<Base64> {
    const relay = await this.initializeRelay(url);
    const guestPk = this.getGuestKey(guestKey);
    const payload = encrypt ? await this.encodeMessage(guestKey, message) : message;
    const toHpk = Utils.toBase64(await this.nacl.h2(Utils.fromBase64(guestPk)));

    const [token] = await this.runRelayCommand(relay, RelayCommand.upload, { to: toHpk, payload });
    return token;
  }

  /**
   * Downloads all messages from a relay, decrypts them with a relay key,
   * and then parses each message to find out if it's a text message, file message,
   * or if it can't be decrypted because HPK is missing in the keyring.
   * Returns an array of mixed messages
   */
  async download(url: string): Promise<ZaxParsedMessage[]> {
    const relay = await this.initializeRelay(url);
    const response = await this.runRelayCommand(relay, RelayCommand.download);
    const messages: ZaxRawMessage[] = await this.decryptResponse(relay, response);

    const parsedMessages: ZaxParsedMessage[] = [];
    for (const message of messages) {
      const senderTag = this.keyRing.getTagByHpk(message.from);
      if (!senderTag) {
        parsedMessages.push(await this.parsePlainMessage(message));
      } else if (message.kind === 'message') {
        parsedMessages.push(await this.parseTextMessage(message, senderTag));
      } else if (message.kind === 'file') {
        parsedMessages.push(await this.parseFileMessage(message, senderTag));
      } else {
        throw new Error('[Mailbox] download - Unknown message type');
      }
    }
    return parsedMessages;
  }

  /**
   * Marks a raw Zax message as one that can't be decrypted,
   * because sender's HPK is not found in the keyring
   */
  private async parsePlainMessage({ data, time, from, nonce }: ZaxRawMessage): Promise<ZaxPlainMessage> {
    return { data, time, from, nonce, kind: ZaxMessageKind.plain };
  }

  /**
   * Decrypts a message that represents uploaded file metadata
   */
  private async parseFileMessage(message: ZaxRawMessage, senderTag: string): Promise<ZaxFileMessage> {
    const { nonce, ctext, uploadID } = JSON.parse(message.data);
    const data: FileUploadMetadata = await this.decodeMessage(senderTag, nonce, ctext);
    return { data, time: message.time, senderTag, uploadID, nonce, kind: ZaxMessageKind.file };
  }

  /**
   * Attempts to decrypt a regular encrypted Zax message. Returns plain message if it was sent encrypted
   */
  private async parseTextMessage(message: ZaxRawMessage, senderTag: string): Promise<ZaxTextMessage> {
    let data = await this.decodeMessage(senderTag, message.nonce, message.data);
    // If the message was sent unencrypted, the line above will return `null`
    if (!data) {
      data = message.data;
    }
    return ({ data, time: message.time, senderTag, nonce: message.nonce, kind: ZaxMessageKind.message });
  }

  /**
   * Returns the number of messages in the mailbox on a given relay
   */
  async count(url: string): Promise<number> {
    const relay = await this.initializeRelay(url);
    const response = await this.runRelayCommand(relay, RelayCommand.count);
    return await this.decryptResponse(relay, response);
  }

  /**
  * Deletes messages from a relay given a list of base64 message nonces,
  * and returns the number of remaining messages
  */
  async delete(url: string, nonceList: Base64[]): Promise<number> {
    const relay = await this.initializeRelay(url);
    const [response] = await this.runRelayCommand(relay, RelayCommand.delete, { payload: nonceList });
    return parseInt(response, 10);
  }

  /**
  * Gets the status of a previously sent Zax message by a storage token.
  * Returns "time to live" in seconds or a negative value if it's not applicable.
  * See `MessageStatusResponse` values for reference
  */
  async messageStatus(url: string, storageToken: Base64): Promise<MessageStatusResponse | number> {
    const relay = await this.initializeRelay(url);
    const [response] = await this.runRelayCommand(relay, RelayCommand.messageStatus, { token: storageToken });
    const status = parseInt(response, 10);
    return status;
  }

  // ---------- Relay file commands (public API) ----------

  /**
   * Asks Zax to start a new upload session, and returns a unique file identifier
   * required to upload file chunks.
   */
  async startFileUpload(guest: string, url: string,
    rawMetadata: FileUploadMetadata): Promise<StartFileUploadResponse> {
    const relay = await this.initializeRelay(url);
    const guestPk = this.getGuestKey(guest);
    const toHpk = Utils.toBase64(await this.nacl.h2(Utils.fromBase64(guestPk)));

    const secretKey = await this.nacl.random_bytes(this.nacl.crypto_secretbox_KEYBYTES);
    rawMetadata.skey = Utils.toBase64(secretKey);

    const metadata = await this.encodeMessage(guest, rawMetadata);

    const response = await this.runRelayCommand(relay, RelayCommand.startFileUpload, {
      to: toHpk,
      file_size: rawMetadata.orig_size,
      metadata
    });

    const decrypted = await this.decryptResponse(relay, response);
    // append symmetric secret key (unique for this upload session) to the server response
    decrypted.skey = secretKey;
    return decrypted;
  }

  /**
   * Encrypts the file chunk symmetrically and transfers it to a relay
   */
  async uploadFileChunk(url: string, uploadID: string, chunk: Uint8Array,
    part: number, totalParts: number, skey: Uint8Array): Promise<UploadFileChunkResponse> {
    const relay = await this.initializeRelay(url);
    const encodedChunk = await this.encodeMessageSymmetric(chunk, skey);
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
    const relay = await this.initializeRelay(url);
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
   * Downloads a binary chunk of a file from a relay by a given uploadID.  The total number of chunks
   * can be retrieved via a `getFileStatus` request
   */
  async downloadFileChunk(url: string, uploadID: string, part: number, skey: Uint8Array): Promise<Uint8Array | null> {
    const relay = await this.initializeRelay(url);
    const response = await this.runRelayCommand(relay, RelayCommand.downloadFileChunk, { uploadID, part });
    const [nonce, ctext, fileCtext] = response;
    const decoded = await relay.decodeMessage(nonce, ctext);
    return await this.decodeMessageSymmetric(decoded.nonce, fileCtext, skey);
  }

  /**
   * Deletes a file from the relay (or all chunks uploaded so far, if the upload was not completed).
   * Can be called by either the sender or recipient
   */
  async deleteFile(url: string, uploadID: string): Promise<DeleteFileResponse> {
    const relay = await this.initializeRelay(url);
    const response = await this.runRelayCommand(relay, RelayCommand.deleteFile, { uploadID });
    return await this.decryptResponse(relay, response);
  }

  // ---------- Dealing with Relay ----------

  /**
   * Gets a singleton Relay instance, and reconnects to a relay if a previous token has expired
   */
  private async initializeRelay(url: string): Promise<Relay> {
    const relay = await Relay.getInstance(url);
    if (relay.isTokenExpired) {
      await this.connectToRelay(url);
    }
    return relay;
  }

  /**
   * Encrypts the payload of the command and sends it to a relay
   */
  private async runRelayCommand(relay: Relay, command: RelayCommand, params?: any, ctext?: string): Promise<string[]> {
    params = { cmd: command, ...params };
    const hpk = await this.getHpk();
    const message = await relay.encodeMessage(params);
    return await relay.runCmd(command, hpk, message, ctext);
  }

  /**
   * Parses relay's response to a command, for those commands that expect an encrypted message in return.
   * Two lines of POST response will be nonce and ctext
   */
  private async decryptResponse(relay: Relay, response: string[]) {
    const [nonce, ctext] = response;
    return await relay.decodeMessage(nonce, ctext);
  }

  // ---------- Message encoding / decoding ----------

  /**
   * Encodes a free-form object `message` to the guest key of a guest already
   * added to the keyring
   */
  async encodeMessage(guest: string, message: any): Promise<EncryptedMessage> {
    const guestPk = this.getGuestKey(guest);
    const privateKey = this.keyRing.getPrivateCommKey();

    return await NaCl.rawEncodeMessage(message, Utils.fromBase64(guestPk), Utils.fromBase64(privateKey));
  }

  /**
   * Decodes a ciphertext from a guest key already in our keyring with this nonce
   */
  async decodeMessage(guest: string, nonce: Base64, ctext: Base64): Promise<any> {
    const guestPk = this.getGuestKey(guest);
    const privateKey = this.keyRing.getPrivateCommKey();

    return await NaCl.rawDecodeMessage(Utils.fromBase64(nonce), Utils.fromBase64(ctext),
      Utils.fromBase64(guestPk), Utils.fromBase64(privateKey));
  }

  /**
   * Encodes a binary message with `secretbox` (used for file chunk encryption)
   */
  private async encodeMessageSymmetric(message: Uint8Array, secretKey: Uint8Array): Promise<EncryptedMessage> {
    const nonce = await NaCl.makeNonce();
    const ctext = await this.nacl.crypto_secretbox(message, nonce, secretKey);
    return {
      nonce: Utils.toBase64(nonce),
      ctext: Utils.toBase64(ctext)
    };
  }

  /**
   * Decodes a binary message with `secretbox_open` (used for file chunk decryption)
   */
  private async decodeMessageSymmetric(nonce: Base64, ctext: Base64,
    secretKey: Uint8Array): Promise<Uint8Array | null> {
    return await this.nacl.crypto_secretbox_open(Utils.fromBase64(ctext), Utils.fromBase64(nonce), secretKey);
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
}

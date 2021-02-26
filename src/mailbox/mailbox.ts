import { NaCl } from '../nacl/nacl';
import { NaClDriver } from '../nacl/nacl-driver.interface';
import { KeyRing } from '../keyring/keyring';
import { Base64, Utils } from '../utils/utils';
import { config } from '../config';
import { EncryptedMessage, Relay } from '../relay/relay';
import {
  StartFileUploadResponse,
  UploadFileChunkResponse,
  FileStatusResponse,
  DeleteFileResponse,
  MessageStatusResponse,
  FileUploadMetadata,
  ZaxRawMessage,
  ZaxFileMessage,
  ZaxPlainMessage,
  ZaxTextMessage,
  ParsedZaxMessage
} from '../zax.interface';
import { Keys } from '../keys/keys';
import { RelaysService } from '../relay/relays.service';

/**
 * Mailbox class represents a wrapper around a Keyring that allows to exchange
 * encrypted messages with other Mailboxes via a relay
 */
export class Mailbox {
  public keyRing: KeyRing;
  public identity: string;

  private nacl: NaClDriver;
  private sessionKeys: Map<string, Keys> = new Map();

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
   * Generates and stores a pair of keys required to start a relay session.
   * If keys were generated earlier, returns the stored keys.
   * Each session with each Zax relay creates its own temporary session keys
   */
  private async getSessionKey(sessionId: string, forceNew?: boolean): Promise<Keys> {
    const existingKey = this.sessionKeys.get(sessionId);
    if (!forceNew && existingKey) {
      return existingKey;
    }

    const keypair = await this.nacl.crypto_box_keypair();
    const keys = new Keys(keypair);
    this.sessionKeys.set(sessionId, keys);
    return keys;
  }

  /**
   * Establishes a session, exchanges temp keys and proves our ownership of this
   * Mailbox to this specific relay. This is the first function to start
   * communications with any relay. Returns the number of messages in the mailbox
   */
  async connectToRelay(url: string): Promise<number> {
    const relay = await RelaysService.getRelay(url);
    const relayPublicKey = await relay.openConnection();
    if (!relay.relayToken) {
      throw new Error('[Relay] No relay token found, fetch it from the relay first');
    }

    const key = await this.getSessionKey(relay.relayId(), true);
    const clientTempPk = Utils.fromBase64(key.publicKey);

    await this.keyRing.addTempGuest(relay.relayId(), relayPublicKey, config.RELAY_TOKEN_TIMEOUT);

    //  Alice creates a 32 byte session signature as h₂(a_temp_pk, relayToken, clientToken)
    const signature = new Uint8Array([...clientTempPk, ...relay.relayToken, ...relay.clientToken]);
    const h2Signature = await this.nacl.h2(signature);
    const encryptedSignature = await this.encodeMessage(relay.relayId(), h2Signature);

    const payload = {
      pub_key: this.keyRing.getPubCommKey(),
      nonce: encryptedSignature.nonce,
      ctext: encryptedSignature.ctext
    };
    const outer = await this.encodeMessage(relay.relayId(), payload, true);
    const messagesNumber = await relay.prove(outer, key.publicKey);
    return parseInt(messagesNumber, 10);
  }

  // ---------- Relay message commands (public API) ----------

  /**
   * Sends a free-form object to a guest we already have in our keyring. Set `encrypt` to `false` to
   * send a plaintext message. Returns a token that can be used with `messageStatus` command to check
   * the status of the message
   */
  /* eslint-disable @typescript-eslint/explicit-module-boundary-types, @typescript-eslint/no-explicit-any */
  async upload(url: string, guestKey: string, message: any, encrypt = true): Promise<Base64> {
    const relay = await RelaysService.getRelay(url);
    const guestPk = this.keyRing.getGuestKey(guestKey);
    if (!guestPk) {
      throw new Error(`[Mailbox] upload: Don't know guest ${guestKey}`);
    }

    const payload = encrypt ? await this.encodeMessage(guestKey, message) : message;
    const toHpk = Utils.toBase64(await this.nacl.h2(Utils.fromBase64(guestPk)));

    const [token] = await this.runRelayCommand(relay, 'upload', { to: toHpk, payload });
    return token;
  }

  /**
   * Downloads all messages from a relay, decrypts them with a relay key,
   * and then parses each message to find out if it's a text message, file message,
   * or if it can't be decrypted because HPK is missing in the keyring.
   * Returns an array of mixed messages
   */
  async download(url: string): Promise<ParsedZaxMessage[]> {
    const relay = await RelaysService.getRelay(url);
    const response = await this.runRelayCommand(relay, 'download');
    const messages: ZaxRawMessage[] = await this.decryptResponse(relay, response);

    const parsedMessages: ParsedZaxMessage[] = [];
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
    return { data, time, from, nonce, kind: 'plain' };
  }

  /**
   * Decrypts a message that represents uploaded file metadata
   */
  private async parseFileMessage(message: ZaxRawMessage, senderTag: string): Promise<ZaxFileMessage> {
    const { nonce, ctext, uploadID } = JSON.parse(message.data);
    const data: FileUploadMetadata = await this.decodeMessage(senderTag, nonce, ctext);
    return { data, time: message.time, senderTag, uploadID, nonce, kind: 'file' };
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
    return ({ data, time: message.time, senderTag, nonce: message.nonce, kind: 'message' });
  }

  /**
   * Returns the number of messages in the mailbox on a given relay
   */
  async count(url: string): Promise<number> {
    const relay = await RelaysService.getRelay(url);
    const response = await this.runRelayCommand(relay, 'count');
    return await this.decryptResponse(relay, response);
  }

  /**
  * Deletes messages from a relay given a list of base64 message nonces,
  * and returns the number of remaining messages
  */
  async delete(url: string, nonceList: Base64[]): Promise<number> {
    const relay = await RelaysService.getRelay(url);
    const [response] = await this.runRelayCommand(relay, 'delete', { payload: nonceList });
    return parseInt(response, 10);
  }

  /**
  * Gets the status of a previously sent Zax message by a storage token.
  * Returns "time to live" in seconds or 0 if the message is not found
  */
  async messageStatus(url: string, storageToken: Base64): Promise<number> {
    const relay = await RelaysService.getRelay(url);
    const [response] = await this.runRelayCommand(relay, 'messageStatus', { token: storageToken });
    const status = parseInt(response, 10);
    if (status === MessageStatusResponse.MissingKey || status === MessageStatusResponse.NeverExpires) {
      return 0;
    }
    return status;
  }

  // ---------- Relay file commands (public API) ----------

  /**
   * Asks Zax to start a new upload session, and returns a unique file identifier
   * required to upload file chunks.
   */
  async startFileUpload(guest: string, url: string,
    rawMetadata: FileUploadMetadata): Promise<StartFileUploadResponse> {
    const relay = await RelaysService.getRelay(url);
    const guestPk = this.keyRing.getGuestKey(guest);
    if (!guestPk) {
      throw new Error(`[Mailbox] startFileUpload: Don't know guest ${guest}`);
    }
    const toHpk = Utils.toBase64(await this.nacl.h2(Utils.fromBase64(guestPk)));

    const secretKey = await this.nacl.random_bytes(this.nacl.crypto_secretbox_KEYBYTES);
    rawMetadata.skey = Utils.toBase64(secretKey);

    const metadata = await this.encodeMessage(guest, rawMetadata);

    const response = await this.runRelayCommand(relay, 'startFileUpload', {
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
    const relay = await RelaysService.getRelay(url);
    const encodedChunk = await this.encodeMessageSymmetric(chunk, skey);
    const response = await this.runRelayCommand(relay, 'uploadFileChunk', {
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
    const relay = await RelaysService.getRelay(url);
    const response = await this.runRelayCommand(relay, 'fileStatus', { uploadID });
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
    const relay = await RelaysService.getRelay(url);
    const response = await this.runRelayCommand(relay, 'downloadFileChunk', { uploadID, part });
    const [nonce, ctext, fileCtext] = response;
    const decoded = await this.decodeMessage(relay.relayId(), nonce, ctext, true);
    return await this.decodeMessageSymmetric(decoded.nonce, fileCtext, skey);
  }

  /**
   * Deletes a file from the relay (or all chunks uploaded so far, if the upload was not completed).
   * Can be called by either the sender or recipient
   */
  async deleteFile(url: string, uploadID: string): Promise<DeleteFileResponse> {
    const relay = await RelaysService.getRelay(url);
    const response = await this.runRelayCommand(relay, 'deleteFile', { uploadID });
    return await this.decryptResponse(relay, response);
  }

  // ---------- Dealing with Relay ----------

  /**
   * Encrypts the payload of the command and sends it to a relay
   */
  /* eslint-disable @typescript-eslint/no-explicit-any */
  private async runRelayCommand(relay: Relay, command: string, params?: any, ctext?: string): Promise<string[]> {
    params = { cmd: command, ...params };
    const hpk = await this.getHpk();
    const message = await this.encodeMessage(relay.relayId(), params, true);
    return await relay.runCmd(command, hpk, message, ctext);
  }

  /**
   * Parses relay's response to a command, for those commands that expect an encrypted message in return.
   * Two lines of POST response will be nonce and ctext
   */
  private async decryptResponse(relay: Relay, response: string[]) {
    const [nonce, ctext] = response;
    const decoded = await this.decodeMessage(relay.relayId(), nonce, ctext, true);
    return decoded;
  }

  // ---------- Message encoding / decoding ----------

  /**
   * Encodes a free-form object `message` to the guest key of a guest already
   * added to the keyring. If the session flag is set, we will look for keys in
   * temporary, not the persistent collection of session keys
   */
  /* eslint-disable @typescript-eslint/explicit-module-boundary-types, @typescript-eslint/no-explicit-any */
  async encodeMessage(guest: string, message: any, session = false): Promise<EncryptedMessage> {
    const guestPk = this.keyRing.getGuestKey(guest);
    if (!guestPk) {
      throw new Error(`[Mailbox] encodeMessage: Don't know guest ${guest}`);
    }

    let privateKey = this.keyRing.commKey.privateKey;

    const sessionKey = this.sessionKeys.get(guest);
    if (session && sessionKey) {
      privateKey = sessionKey.privateKey;
    }

    if (!(message instanceof Uint8Array)) {
      message = await this.nacl.encode_utf8(JSON.stringify(message));
    }

    return await this.rawEncodeMessage(message, Utils.fromBase64(guestPk), Utils.fromBase64(privateKey));
  }

  /**
   * Encodes a binary message with `cryptobox`
   */
  private async rawEncodeMessage(message: Uint8Array, pkTo: Uint8Array,
    skFrom: Uint8Array, nonceData?: number): Promise<EncryptedMessage> {
    const nonce = await this.makeNonce(nonceData);
    const ctext = await this.nacl.crypto_box(message, nonce, pkTo, skFrom);
    return {
      nonce: Utils.toBase64(nonce),
      ctext: Utils.toBase64(ctext)
    };
  }

  /**
   * Decodes a ciphertext from a guest key already in our keyring with this
   * nonce. If session flag is set, looks for keys in temporary, not the
   * persistent collection of session keys
   */
  /* eslint-disable @typescript-eslint/no-explicit-any */
  async decodeMessage(guest: string, nonce: Base64, ctext: Base64, session = false): Promise<any> {
    const guestPk = this.keyRing.getGuestKey(guest);
    if (!guestPk) {
      throw new Error(`[Mailbox] decodeMessage: Don't know guest ${guest}`);
    }

    let privateKey = this.keyRing.commKey.privateKey;

    const sessionKey = this.sessionKeys.get(guest);
    if (session && sessionKey) {
      privateKey = sessionKey.privateKey;
    }

    return await this.rawDecodeMessage(Utils.fromBase64(nonce), Utils.fromBase64(ctext),
      Utils.fromBase64(guestPk), Utils.fromBase64(privateKey));
  }

  /**
   * Decodes a binary message with `cryptobox_open`
   */
  private async rawDecodeMessage(nonce: Uint8Array, ctext: Uint8Array,
    pkFrom: Uint8Array, skTo: Uint8Array): Promise<any> {
    const data = await this.nacl.crypto_box_open(ctext, nonce, pkFrom, skTo);
    if (data) {
      const utf8 = await this.nacl.decode_utf8(data);
      return JSON.parse(utf8);
    }

    return data;
  }

  /**
   * Encodes a binary message with `secretbox` (used for file chunk encryption)
   */
  private async encodeMessageSymmetric(message: Uint8Array, secretKey: Uint8Array): Promise<EncryptedMessage> {
    const nonce = await this.makeNonce();
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

  // ---------- Nonce helpers ----------

  /**
   * Makes a timestamp nonce that a relay expects for any crypto operations.
   * Timestamp is the first 8 bytes, the rest is random, unless custom `data`
   * is specified. `data` will be packed as next 4 bytes after timestamp.
   */
  private async makeNonce(data?: number): Promise<Uint8Array> {
    const nonce = await this.nacl.crypto_box_random_nonce();
    let headerLen;
    if (nonce.length !== this.nacl.crypto_box_NONCEBYTES) {
      throw new Error('[Mailbox] Wrong crypto_box nonce length');
    }
    // split timestamp integer as an array of bytes
    headerLen = 8; // max timestamp size
    const aTime = this.itoa(Math.floor(Date.now() / 1000));

    if (data) {
      headerLen += 4; // extra 4 bytes for custom data
    }

    // zero out nonce header area
    nonce.fill(0, 0, headerLen);
    // copy the timestamp into the first 8 bytes of nonce
    nonce.set(aTime, 8 - aTime.length);
    // copy data if present
    if (data) {
      const aData = this.itoa(data);
      nonce.set(aData, 12 - aData.length);
    }
    return nonce;
  }

  /**
   * Splits an integer into an array of bytes
   */
  private itoa(num: number): Uint8Array {
    // calculate length first
    let hex = num.toString(16);
    hex = hex.length & 1 ? `0${hex}` : hex;
    const len = hex.length / 2;
    const byteArray = new Uint8Array(len);

    for (let j = 0, i = 0; i < hex.length; i += 2, j++) {
      byteArray[j] = parseInt(hex[i] + hex[i + 1], 16);
    }
    return byteArray;
  }
}

import { NaCl } from '../nacl/nacl';
import { NaClDriver } from '../nacl/nacl-driver.interface';
import { KeyRing } from '../keyring/keyring';
import { Base64, Utils } from '../utils/utils';
import { EncryptedMessage, Relay } from '../relay/relay';
import { Keys } from '../keys/keys';

interface ZaxMessage {
  data?: Base64;
  time: number;
  from: Base64;
  fromTag?: string;
  nonce: Base64;
  ctext?: Base64;
  kind: 'message' | 'file';
  msg?: any;
}

interface UploadedMessageData {
  token: Base64;
  nonce: Base64;
}

interface UploadFileChunkResponse {
  status: string;
}

interface FileStatusResponse {
  status: 'COMPLETE' | 'UPLOADING' | 'START' | 'NOT_FOUND';
  total_chunks: number;
  file_size: number;
  bytes_stored: number;
}

interface DeleteFileResponse {
  status: 'OK' | 'NOT_FOUND';
}

/**
 * Low-level operations with Zax relay.
 */
export class Mailbox {
  public keyRing: KeyRing;

  private nacl: NaClDriver;
  private identity?: string;
  private sessionKeys: Map<string, Keys> = new Map();

  private constructor(naclDriver: NaClDriver, keyRing: KeyRing) {
    this.nacl = naclDriver;
    this.keyRing = keyRing;
  }

  static async new(id: string, backup?: string): Promise<Mailbox> {
    const nacl = NaCl.getInstance();
    const keyRing = backup ? await KeyRing.fromBackup(id, backup) : await KeyRing.new(id);
    const mbx = new Mailbox(nacl, keyRing);
    mbx.identity = id;
    return mbx;
  }

  // -------------------------------- Alternative initializers --------------------------------

  // You can create a Mailbox where the secret identity key is derived from a well-known seed
  static async fromSeed(id: string, seed: Uint8Array): Promise<Mailbox> {
    const mbx = await this.new(id);
    await mbx.keyRing.setCommFromSeed(seed);
    return mbx;
  }

  // You can also create a Mailbox if you already know the secret identity key
  static async fromSecKey(id: string, rawSecretKey: Uint8Array): Promise<Mailbox> {
    const mbx = await this.new(id);
    await mbx.keyRing.setCommFromSecKey(rawSecretKey);
    return mbx;
  }

  // You can also create a Mailbox from backup string
  static async fromBackup(id: string, backup: string): Promise<Mailbox> {
    return await this.new(id, backup);
  }

  // This is the HPK (hash of the public key) of your mailbox. This is what Zax relays
  // use as the universal address of your mailbox.
  async getHpk(): Promise<Base64> {
    return await this.keyRing.getHpk();
  }

  // This is your public identity and default communication key. Your
  // correspondents can know it, whereas Relays do not need it (other than
  // temporarily for internal use during the ownership proof)
  getPubCommKey(): string {
    return this.keyRing.getPubCommKey();
  }

  async createSessionKey(session_id: string, forceNew: boolean): Promise<Keys> {
    const existingKey = this.sessionKeys.get(session_id);
    if (!forceNew && existingKey) {
      return Promise.resolve(existingKey);
    }

    const keypair = await this.nacl.crypto_box_keypair();
    const keys = new Keys(keypair);
    this.sessionKeys.set(session_id, keys);
    return keys;
  }

  async connectToRelay(relay: Relay) {
    await relay.openConnection();
    await relay.connectMailbox(this);
  }

  // ------------------------------ Relay message commands (public API) ------------------------------

  async upload(relay: Relay, guestKey: string, message: any): Promise<UploadedMessageData> {
    const guestPk = this.keyRing.getGuestKey(guestKey);
    if (!guestPk) {
      throw new Error(`upload: don't know guest ${guestKey}`);
    }

    const payload = await this.encodeMessage(guestKey, message);
    const toHpk = await this.nacl.h2(Utils.fromBase64(guestPk));

    const response = await this.runRelayCommand(relay, 'upload', { to: Utils.toBase64(toHpk), payload });
    const token = response[0];
    return { token, nonce: payload.nonce };
  }

  /**
   * Downloads messages from a relay and decrypts the contents.
   */
  async download(relay: Relay): Promise<ZaxMessage[]> {
    const response = await this.runRelayCommand(relay, 'download');
    const messages: ZaxMessage[] = await this.decryptResponse(relay, response);

    for (const msg of messages) {
      const tag = this.keyRing.getTagByHpk(msg.from);
      if (!tag) {
        continue;
      }

      msg.fromTag = tag;

      if (msg.kind === 'message' && msg.data) {
        const originalMsg = await this.decodeMessage(tag, msg.nonce, msg.data);
        if (originalMsg) {
          msg.msg = originalMsg;
          delete msg.data;
        }
      } else if (msg.kind === 'file' && msg.data) {
        const data = JSON.parse(msg.data);
        const originalMsg = await this.decodeMessage(tag, msg.nonce, data.ctext);
        originalMsg.uploadID = data.uploadID;
        msg.msg = originalMsg;
        delete msg.data;
      } else {
        throw new Error('download - unknown message type');
      }
    }

    return messages;
  }

  /**
   * Returns the number of messages in the mailbox on a given relay.
   */
  async count(relay: Relay): Promise<number> {
    const response = await this.runRelayCommand(relay, 'count');
    return await this.decryptResponse(relay, response);
  }

  /**
  * Deletes messages from a relay given a list of base64 message nonces,
  * and returns the number of remaining messages.
  */
  async delete(relay: Relay, nonceList: Base64[]): Promise<number> {
    const response = await this.runRelayCommand(relay, 'delete', { payload: nonceList });
    return parseInt(response[0], 10);
  }

  async messageStatus(relay: Relay, storageToken: Base64): Promise<number> {
    const response = await this.runRelayCommand(relay, 'messageStatus', { token: storageToken });
    return parseInt(response[0], 10);
  }

  // ------------------------------ Relay file commands (public API) ------------------------------

  async startFileUpload(guest: string, relay: Relay, rawMetadata: any) {
    const guestPk = this.keyRing.getGuestKey(guest);
    if (!guestPk) {
      throw new Error(`relaySend: don't know guest ${guest}`);
    }
    const toHpk = await this.nacl.h2(Utils.fromBase64(guestPk));

    const secretKey = await this.nacl.random_bytes(this.nacl.crypto_secretbox_KEYBYTES);
    rawMetadata.skey = Utils.toBase64(secretKey);

    const metadata = await this.encodeMessage(guest, rawMetadata);

    const response = await this.runRelayCommand(relay, 'startFileUpload', {
      to: Utils.toBase64(toHpk),
      file_size: rawMetadata.orig_size,
      metadata
    });

    const decrypted = await this.decryptResponse(relay, response);
    decrypted.skey = secretKey;
    return decrypted;
  }

  async uploadFileChunk(relay: Relay, uploadID: string, chunk: Uint8Array,
    part: number, totalParts: number, skey: Uint8Array): Promise<UploadFileChunkResponse> {
    const encodedChunk = await this.encodeMessageSymmetric(chunk, skey);
    const response = await this.runRelayCommand(relay, 'uploadFileChunk', {
      uploadID,
      part,
      last_chunk: (totalParts - 1 === part),
      nonce: encodedChunk.nonce
    }, encodedChunk.ctext);
    return await this.decryptResponse(relay, response);
  }

  async getFileStatus(relay: Relay, uploadID: string): Promise<FileStatusResponse> {
    const response = await this.runRelayCommand(relay, 'fileStatus', { uploadID });
    return await this.decryptResponse(relay, response);
  }

  async getFileMetadata(relay: Relay, uploadID: string) {
    const messages = await this.download(relay);
    const fileMessage = messages
      .find(encryptedMessage => encryptedMessage.msg.uploadID === uploadID);
    return fileMessage?.msg;
  }

  async downloadFileChunk(relay: Relay, uploadID: string, part: number, skey: Uint8Array): Promise<Uint8Array | null> {
    const response = await this.runRelayCommand(relay, 'downloadFileChunk', { uploadID, part });
    const [nonce, ctext, fileCtext] = response;
    const decoded = await this.decodeMessage(relay.relayId(), nonce, ctext, true);
    return await this.decodeMessageSymmetric(decoded.nonce, fileCtext, skey);
  }

  async deleteFile(relay: Relay, uploadID: string): Promise<DeleteFileResponse> {
    const response = await this.runRelayCommand(relay, 'deleteFile', { uploadID });
    return await this.decryptResponse(relay, response);
  }

  // ------------------------------ Dealing with Relay ------------------------------

  private async runRelayCommand(relay: Relay, command: string, params?: any, ctext?: string): Promise<string[]> {
    params = { cmd: command, ...params };
    const hpk = await this.getHpk();
    const message = await this.encodeMessage(relay.relayId(), params, true);
    return await relay.runCmd(command, hpk, message, ctext);
  }

  private async decryptResponse(relay: Relay, response: string[]) {
    const [nonce, ctext] = response;
    const decoded = await this.decodeMessage(relay.relayId(), nonce, ctext, true);
    return decoded;
  }

  // ------------------------------ Message encoding / decoding ------------------------------

  // Encodes a free-form object `message` to the guest key of a guest already
  // added to our keyring. If the session flag is set, we will look for keys in
  // temporary, not the persistent collection of session keys. skTag lets you
  // specifiy the secret key in a key ring
  async encodeMessage(guest: string, message: any, session = false, skTag = null): Promise<EncryptedMessage> {
    const guestPk = this.keyRing.getGuestKey(guest);
    if (!guestPk) {
      throw new Error(`encodeMessage: don't know guest ${guest}`);
    }

    let privateKey = this.keyRing.commKey.privateKey;

    const sessionKey = this.sessionKeys.get(guest);
    if (session && sessionKey) {
      privateKey = sessionKey.privateKey;
    }

    if (!(message instanceof Uint8Array)) {
      message = await this.nacl.encode_utf8(JSON.stringify(message));
    }

    // TODO: add whatever neccesary int32 id/counter logic and provide nonceData as last param
    // That int32 (on receive/decode) can be restored via _nonceData()
    return await this.rawEncodeMessage(message, Utils.fromBase64(guestPk), Utils.fromBase64(privateKey));
  }

  async rawEncodeMessage(message: Uint8Array, pkTo: Uint8Array,
    skFrom: Uint8Array, nonceData?: number): Promise<EncryptedMessage> {
    const nonce = await this.makeNonce(nonceData);
    const ctext = await this.nacl.crypto_box(message, nonce, pkTo, skFrom);
    return {
      nonce: Utils.toBase64(nonce),
      ctext: Utils.toBase64(ctext)
    };
  }

  async decodeMessage(guest: string, nonce: Base64, ctext: Base64, session = false, skTag = null) {
    const guestPk = this.keyRing.getGuestKey(guest);
    if (!guestPk) {
      throw new Error(`decodeMessage: don't know guest ${guest}`);
    }

    let privateKey = this.keyRing.commKey.privateKey;

    const sessionKey = this.sessionKeys.get(guest);
    if (session && sessionKey) {
      privateKey = sessionKey.privateKey;
    }

    return await this.rawDecodeMessage(Utils.fromBase64(nonce), Utils.fromBase64(ctext),
      Utils.fromBase64(guestPk), Utils.fromBase64(privateKey));
  }

  async rawDecodeMessage(nonce: Uint8Array, ctext: Uint8Array, pkFrom: Uint8Array, skTo: Uint8Array) {
    const data = await this.nacl.crypto_box_open(ctext, nonce, pkFrom, skTo);
    if (data) {
      const utf8 = await this.nacl.decode_utf8(data);
      return JSON.parse(utf8);
    }

    return data;
  }

  async encodeMessageSymmetric(message: Uint8Array, secretKey: Uint8Array): Promise<EncryptedMessage> {
    const nonce = await this.makeNonce();
    const ctext = await this.nacl.crypto_secretbox(message, nonce, secretKey);
    return {
      nonce: Utils.toBase64(nonce),
      ctext: Utils.toBase64(ctext)
    };
  }

  async decodeMessageSymmetric(nonce: Base64, ctext: Base64, secretKey: Uint8Array) {
    return await this.nacl.crypto_secretbox_open(Utils.fromBase64(ctext), Utils.fromBase64(nonce), secretKey);
  }

  // ------------------------------ Nonce helpers ------------------------------

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

import { NaCl } from '../nacl/nacl';
import { NaClDriver } from '../nacl/nacl-driver.interface';
import { KeyRing } from '../keyring/keyring';
import { Base64, Utils } from '../utils/utils';
import { Relay } from '../relay/relay';
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

interface EncryptedMessage {
  nonce: Base64;
  ctext: Base64;
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
  async getHpk(): Promise<string> {
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

  async encodeMessageSymmetric(message: Uint8Array, secretKey: Uint8Array) {
    const nonce = await this.makeNonce();
    const ctext = await this.nacl.crypto_secretbox(message, nonce, secretKey);
    return {
      nonce: Utils.toBase64(nonce),
      ctext: Utils.toBase64(ctext)
    };
  }

  async decodeMessageSymmetric(nonce: Uint8Array, ctext: Uint8Array, secretKey: Uint8Array) {
    return await this.nacl.crypto_secretbox_open(ctext, nonce, secretKey);
  }

  async connectToRelay(relay: Relay) {
    await relay.openConnection();
    await relay.connectMailbox(this);
  }

  // ------------------------------ Relay message commands (public API) ------------------------------

  async upload(relay: Relay, guestKey: string, message: any) {
    const guestPk = this.keyRing.getGuestKey(guestKey);
    if (!guestPk) {
      throw new Error(`upload: don't know guest ${guestKey}`);
    }

    const payload = await this.encodeMessage(guestKey, message);
    const toHpk = await this.nacl.h2(Utils.fromBase64(guestPk));

    const token = await relay.runCmd('upload', this, {
      to: Utils.toBase64(toHpk),
      payload
    });
    return {
      token,
      nonce: payload.nonce,
      ctext: payload.ctext
    };
  }

  /**
   * Downloads messages from a relay and decrypts the contents.
   */
  async download(relay: Relay): Promise<ZaxMessage[]> {
    const messages: ZaxMessage[] = await relay.runCmd('download', this);

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
    return await relay.runCmd('count', this);
  }

  /**
  * Deletes messages from a relay given a list of base64 message nonces,
  * and returns the number of remaining messages.
  */
  async delete(relay: Relay, nonceList: Base64[]): Promise<number> {
    return await relay.runCmd('delete', this, { payload: nonceList });
  }

  async messageStatus(relay: Relay, storageToken: Base64): Promise<number> {
    return await relay.runCmd('messageStatus', this, { token: storageToken });
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

    const response = await relay.runCmd('startFileUpload', this, {
      to: Utils.toBase64(toHpk),
      file_size: rawMetadata.orig_size,
      metadata
    });
    response.skey = secretKey;
    return response;
  }

  async uploadFileChunk(relay: Relay, uploadID: string, chunk: Uint8Array,
    part: number, totalParts: number, skey: Uint8Array) {
    const encodedChunk = await this.encodeMessageSymmetric(chunk, skey);
    return await relay.runCmd('uploadFileChunk', this, {
      uploadID,
      part,
      last_chunk: (totalParts - 1 === part),
      nonce: encodedChunk.nonce
    }, encodedChunk.ctext);
  }

  async getFileStatus(relay: Relay, uploadID: string) {
    return await relay.runCmd('fileStatus', this, { uploadID });
  }

  async getFileMetadata(relay: Relay, uploadID: string) {
    const messages = await this.download(relay);
    const fileMessage = messages
      .find(encryptedMessage => encryptedMessage.msg.uploadID === uploadID);
    return fileMessage?.msg;
  }

  async downloadFileChunk(relay: Relay, uploadID: string, part: number, skey: Uint8Array) {
    const encodedChunk = await relay.runCmd('downloadFileChunk', this, { uploadID, part });
    return await this.decodeMessageSymmetric(Utils.fromBase64(encodedChunk.nonce),
      Utils.fromBase64(encodedChunk.ctext), skey);
  }

  async deleteFile(relay: Relay, uploadID: string) {
    return await relay.runCmd('deleteFile', this, { uploadID });
  }

  // ------------------------------ Nonce helpers ------------------------------

  // Makes a timestamp nonce that a relay expects for any crypto operations.
  // timestamp is the first 8 bytes, the rest is random, unless custom 'data'
  // is specified. 'data' will be packed as next 4 bytes after timestamp
  private async makeNonce(data?: number) {
    const nonce = await this.nacl.crypto_box_random_nonce();
    let headerLen;
    if (nonce.length !== 24) {
      throw new Error('RNG failed, try again?');
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

  // Split an integer into an array of bytes
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

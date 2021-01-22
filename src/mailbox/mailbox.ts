import { NaCl } from '../nacl/nacl';
import { NaClDriver } from '../nacl/nacl-driver.interface';
import { KeyRing } from '../keyring/keyring';
import { Base64, Utils } from '../utils/utils';
import { Relay } from '../relay/relay';
import { Keys } from '../keys/keys';

/**
 * Low-level operations with Zax relay.
 */
export class Mailbox {
  private nacl: NaClDriver;
  private identity?: string;
  public keyRing?: KeyRing;
  private sessionKeys: Map<string, Keys> = new Map();

  private constructor(naclDriver: NaClDriver) {
    this.nacl = naclDriver;
  }

  static async new(id: string, backup?: string): Promise<Mailbox> {
    const nacl = NaCl.getInstance();
    const mbx = new Mailbox(nacl);
    mbx.identity = id;
    if (backup) {
      mbx.keyRing = await KeyRing.fromBackup(id, backup);
    } else {
      mbx.keyRing = await KeyRing.new(id);
    }
    return mbx;
  }

  // You can create a Mailbox where the secret identity key is derived from a well-known seed
  static async fromSeed(id: string, seed: Uint8Array): Promise<Mailbox> {
    const mbx = await this.new(id);
    await mbx.keyRing?.setCommFromSeed(seed);
    return mbx;
  }

  // You can also create a Mailbox if you already know the secret identity key
  static async fromSecKey(id: string, rawSecretKey: Uint8Array): Promise<Mailbox> {
    const mbx = await this.new(id);
    await mbx.keyRing?.setCommFromSecKey(rawSecretKey);
    return mbx;
  }

  // You can also create a Mailbox from backup string
  static async fromBackup(id: string, backup: string): Promise<Mailbox> {
    return await this.new(id, backup);
  }

  // This is the HPK (hash of the public key) of your mailbox. This is what Zax relays
  // use as the universal address of your mailbox.
  getHpk(): string | undefined {
    return this.keyRing?.hpk ? Utils.toBase64(this.keyRing.hpk) : undefined;
  }

  // This is your public identity and default communication key. Your
  // correspondents can know it, whereas Relays do not need it (other than
  // temporarily for internal use during the ownership proof)
  getPubCommKey(): string | undefined {
    return this.keyRing?.getPubCommKey();
  }

  async createSessionKey(session_id: string, forceNew: boolean) {
    if (!forceNew && this.sessionKeys.has(session_id)) {
      return Promise.resolve(this.sessionKeys.get(session_id));
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
  async encodeMessage(guest: string, message: any, session = false, skTag = null) {
    const guestPk = this.keyRing?.getGuestKey(guest);
    if (!guestPk) {
      throw new Error(`encodeMessage: don't know guest ${guest}`);
    }

    let privateKey;
    privateKey = this.keyRing?.commKey?.privateKey;
    if (!privateKey) {
      throw new Error('encodeMessage: no comm key');
    }

    if (session) {
      privateKey = this.sessionKeys.get(guest)?.privateKey;
    }
    if (!privateKey) {
      throw new Error('encodeMessage: no comm key');
    }

    if (!(message instanceof Uint8Array)) {
      message = await this.nacl.encode_utf8(JSON.stringify(message));
    }

    // TODO: add whatever neccesary int32 id/counter logic and provide nonceData as last param
    // That int32 (on receive/decode) can be restored via _nonceData()
    return await this.rawEncodeMessage(message, Utils.fromBase64(guestPk), Utils.fromBase64(privateKey));
  }

  async rawEncodeMessage(message: Uint8Array, pkTo: Uint8Array, skFrom: Uint8Array, nonceData = null) {
    const nonce = await this.makeNonce(nonceData);
    const ctext = await this.nacl.crypto_box(message, nonce, pkTo, skFrom);
    return { nonce, ctext };
  }

  async decodeMessage(guest: string, nonce: Uint8Array | Base64, ctext: Uint8Array | Base64,
    session = false, skTag = null) {
    const guestPk = this.keyRing?.getGuestKey(guest);
    if (!guestPk) {
      throw new Error(`decodeMessage: don't know guest ${guest}`);
    }

    let privateKey = this.keyRing?.commKey?.privateKey;
    if (!privateKey) {
      throw new Error('decodeMessage: no comm key');
    }

    if (session) {
      privateKey = this.sessionKeys.get(guest)?.privateKey;
    }
    if (!privateKey) {
      throw new Error('decodeMessage: no comm key');
    }

    if (!(nonce instanceof Uint8Array)) {
      nonce = Utils.fromBase64(nonce);
    }

    if (!(ctext instanceof Uint8Array)) {
      ctext = Utils.fromBase64(ctext);
    }

    return await this.rawDecodeMessage(nonce, ctext, Utils.fromBase64(guestPk), Utils.fromBase64(privateKey));
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

  async relaySend(guest: string, message: any, relay: Relay) {
    const guestPk = this.keyRing?.getGuestKey(guest);
    if (!guestPk) {
      throw new Error(`relaySend: don't know guest ${guest}`);
    }

    const encodedMessage = await this.encodeMessage(guest, message);
    const h2 = await this.nacl.h2(Utils.decode_latin1(Utils.fromBase64(guestPk)));
    return await relay.upload(this, h2, encodedMessage);
  }

  async startFileUpload(guest: string, relay: Relay, metadata: any) {
    const guestPk = this.keyRing?.getGuestKey(guest);
    if (!guestPk) {
      throw new Error(`relaySend: don't know guest ${guest}`);
    }
    const h2 = await this.nacl.h2(Utils.decode_latin1(Utils.fromBase64(guestPk)));

    const secretKey = await this.nacl.random_bytes(this.nacl.crypto_secretbox_KEYBYTES);
    metadata.skey = Utils.toBase64(secretKey);

    const encodedMetadata = await this.encodeMessage(guest, metadata);
    await this.connectToRelay(relay);
    const fileSize = metadata.orig_size;
    const response = await relay.startFileUpload(this, h2, fileSize, {
      nonce: Utils.toBase64(encodedMetadata.nonce),
      ctext: Utils.toBase64(encodedMetadata.ctext)
    });
    response.skey = secretKey;
    return response;
  }

  async uploadFileChunk(relay: Relay, uploadID: string, chunk: Uint8Array,
    part: number, totalParts: number, skey: Uint8Array) {
    const encodedChunk = await this.encodeMessageSymmetric(chunk, skey);
    return await relay.uploadFileChunk(this, uploadID, part, totalParts, encodedChunk);
  }

  async getFileStatus(relay: Relay, uploadID: string) {
    return await relay.fileStatus(this, uploadID);
  }

  async getFileMetadata(relay: Relay, uploadID: string) {
    let sender;
    let message;
    const all: any[] = await relay.download(this);
    const mapped = all.find(encryptedMessage => {
      sender = this.keyRing?.getTagByHpk(encryptedMessage.from);
      if (sender && encryptedMessage.kind === 'file') {
        message = JSON.parse(encryptedMessage.data);
        encryptedMessage.ctext = message.ctext;
        return message.uploadID === uploadID;
      }
    });

    if (sender) {
      const originalMessage = await this.decodeMessage(sender, mapped.nonce, mapped.ctext);
      return originalMessage;
    }

    return null;
  }

  async downloadFileChunk(relay: Relay, uploadID: string, part: number, skey: Uint8Array) {
    const encodedChunk = await relay.downloadFileChunk(this, uploadID, part);
    return await this.decodeMessageSymmetric(Utils.fromBase64(encodedChunk.nonce),
      Utils.fromBase64(encodedChunk.ctext), skey);
  }

  async deleteFile(relay: Relay, uploadID: string) {
    return await relay.deleteFile(this, uploadID);
  }

  // Makes a timestamp nonce that a relay expects for any crypto operations.
  // timestamp is the first 8 bytes, the rest is random, unless custom 'data'
  // is specified. 'data' will be packed as next 4 bytes after timestamp
  // Returns a Promise
  private async makeNonce(data: any = null, time = Date.now()) {
    const nonce = await this.nacl.crypto_box_random_nonce();
    let aData, aTime, headerLen, i, j, k, l, ref, ref1, ref2;
    if (!((nonce != null) && nonce.length === 24)) {
      throw new Error('RNG failed, try again?');
    }
    // split timestamp integer as an array of bytes
    headerLen = 8; // max timestamp size
    aTime = this.itoa(Math.floor(time / 1000));
    if (data) {
      headerLen += 4; // extra 4 bytes for custom data
    }

    for (i = j = 0, ref = headerLen; (0 <= ref ? j < ref : j > ref); i = 0 <= ref ? ++j : --j) {
      // zero out nonce header area
      nonce[i] = 0;
    }
    for (i = k = 0, ref1 = aTime.length - 1; (0 <= ref1 ? k <= ref1 : k >= ref1); i = 0 <= ref1 ? ++k : --k) {
      // copy the timestamp into the first 8 bytes of nonce
      nonce[8 - aTime.length + i] = aTime[i];
    }
    if (data) {
      aData = this.itoa(data);
      for (i = l = 0, ref2 = aData.length - 1; (0 <= ref2 ? l <= ref2 : l >= ref2); i = 0 <= ref2 ? ++l : --l) {
        // copy data if present
        nonce[12 - aData.length + i] = aData[i];
      }
    }
    return nonce;
  }

  private itoa(n: number) {
    var floor, i, lg, pw, top;
    if (n <= 0) {
      return new Uint8Array((function() {
        var j, results;
        results = [];
        for (i = j = 0; j <= 7; i = ++j) {
          results.push(0);
        }
        return results;
      })());
    }
    [floor, pw, lg] = [
      Math.floor,
      Math.pow,
      Math.log // aliases
    ];
    top = floor(lg(n) / lg(256));
    return new Uint8Array((function() {
      var j, ref, results;
      results = [];
      for (i = j = ref = top; (ref <= 0 ? j <= 0 : j >= 0); i = ref <= 0 ? ++j : --j) {
        results.push(floor(n / pw(256, i)) % 256);
      }
      return results;
    })());
  }
}

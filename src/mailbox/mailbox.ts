import { NaCl } from '../nacl/nacl';
import { NaClDriver } from '../nacl/nacl-driver.interface';
import { KeyRing } from '../keyring/keyring';
import { Utils } from '../utils/utils';
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

  static async new(identity: string): Promise<Mailbox> {
    const nacl = NaCl.getInstance();
    const mbx = new Mailbox(nacl);
    mbx.identity = identity;
    const keyRing = await KeyRing.new(identity);
    mbx.keyRing = keyRing;
    return mbx;
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
  async encodeMessage(guest: string, message: Uint8Array, session = false, skTag = null) {
    const guestPk = this.keyRing?.getGuestKey(guest);
    if (!guestPk) {
      throw new Error(`encodeMessage: don't know guest ${guest}`);
    }

    const privateKey = this.keyRing?.commKey?.privateKey;
    if (!privateKey) {
      throw new Error(`encodeMessage: no comm key`);
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

  async decodeMessage(guest: string, nonce: Uint8Array, ctext: Uint8Array, session = false, skTag = null) {
    const guestPk = this.keyRing?.getGuestKey(guest);
    if (!guestPk) {
      throw new Error(`decodeMessage: don't know guest ${guest}`);
    }

    const privateKey = this.keyRing?.commKey?.privateKey;
    if (!privateKey) {
      throw new Error(`decodeMessage: no comm key`);
    }
    return await this.rawDecodeMessage(nonce, ctext, Utils.fromBase64(guestPk), Utils.fromBase64(privateKey));
  }

  async rawDecodeMessage(nonce: Uint8Array, ctext: Uint8Array, pkFrom: Uint8Array, skTo: Uint8Array) {
    const data = await this.nacl.crypto_box_open(ctext, nonce, pkFrom, skTo);
    return data;
  }

  // Makes a timestamp nonce that a relay expects for any crypto operations.
  // timestamp is the first 8 bytes, the rest is random, unless custom 'data'
  // is specified. 'data' will be packed as next 4 bytes after timestamp
  // Returns a Promise
  public async makeNonce(data: any = null, time = Date.now()) {
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

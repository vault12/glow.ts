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
  private keyRing?: KeyRing;
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

  getHpk(): string | undefined {
    return this.keyRing?.hpk ? Utils.toBase64(this.keyRing.hpk) : undefined;
  }

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
}

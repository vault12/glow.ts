import { CryptoStorage } from '../crypto-storage/crypto-storage';
import { LocalStorageDriver } from '../crypto-storage/local-storage.driver';
import { Keys } from '../keys/keys';
import { NaCl } from '../nacl/nacl';
import { Utils, Base64 } from '../utils/utils';
import { config } from '../config';

interface KeyRecord {
  pk: Base64;
  hpk: Base64;
  temp: boolean;
}

interface TempKeyTimeout {
  timeoutId: number;
  startTime: number;
}

interface KeyRingBackup {
  [key: string]: string | null | undefined
}

// Manages the set of public keys of counterparties
export class KeyRing {
  public storage?: CryptoStorage;
  public commKey?: Keys;
  public hpk?: Uint8Array;
  public guestKeys: Map<string, KeyRecord>;
  public guestKeyTimeouts: Map<string, TempKeyTimeout>;

  private constructor() {
    this.guestKeys = new Map();
    this.guestKeyTimeouts = new Map();
  }

  static async new(): Promise<KeyRing> {
    const keyRing = new KeyRing();
    keyRing.storage = await CryptoStorage.new(new LocalStorageDriver());
    await keyRing.loadCommKey();
    await keyRing.loadGuestKeys();
    return keyRing;
  }

  getNumberOfGuests(): number {
    return this.guestKeys.size;
  }

  getPubCommKey(): string | undefined {
    return this.commKey?.publicKey;
  }

  getTagByHpk(hpk: string): string | null {
    for (const [key, value] of this.guestKeys) {
      if (value.hpk === hpk) {
        return key;
      }
    }
    return null;
  }

  getGuestKey(guestTag: string): Keys | null {
    const keyRecord = this.guestKeys.get(guestTag);
    if (keyRecord) {
      return new Keys({
        boxPk: Utils.encode_latin1(Utils.fromBase64(keyRecord.pk))
      });
    }
    return null;
  }

  getTimeToGuestExpiration(guestTag: string): number {
    const timeout = this.guestKeyTimeouts.get(guestTag);
    if (timeout) {
      return Math.max(0, config.RELAY_SESSION_TIMEOUT - (Date.now() - timeout.startTime));
    } else {
      return 0;
    }
  }

  private async loadCommKey() {
    if (!this.storage) {
      return;
    }
    const nacl = new NaCl();
    const commKey = await this.getKey('comm_key');
    if (commKey) {
      this.commKey = commKey;
      this.hpk = await nacl.h2(this.commKey.publicKey);
    } else {
      const keypair = await nacl.crypto_box_keypair();
      this.commKey = new Keys(keypair);
      this.hpk = await nacl.h2(this.commKey.publicKey);
      await this.storage.save('comm_key', this.commKey);
    }
  }

  // Backups

  async backup(): Promise<string> {
    const backupObject: KeyRingBackup = {};
    backupObject[config.COMM_KEY_TAG] = this.commKey?.privateKey;

    if (this.getNumberOfGuests() > 0) {
      for (const [key, value] of this.guestKeys) {
        if (key && value) {
          backupObject[key] = value.pk;
        }
      }
    }
    return JSON.stringify(backupObject);
  }

  static async fromBackup(id: string, backup: string): Promise<KeyRing> {
    const backupObject = JSON.parse(backup);
    const strCommKey = Utils.encode_latin1(Utils.fromBase64(backupObject[config.COMM_KEY_TAG]));
    delete backupObject[config.COMM_KEY_TAG];
    const restoredKeyRing = await KeyRing.new();
    restoredKeyRing.commFromSecKey(strCommKey);
    for (const [key, value] of Object.entries(backupObject)) {
      await restoredKeyRing.addGuest(key, value as string);
    }
    return restoredKeyRing;
  }

  async commFromSeed(seed: Uint8Array): Promise<void> {
    if (!this.storage) {
      return;
    }
    const nacl = new NaCl();
    this.commKey = new Keys(await nacl.crypto_box_keypair_from_seed(seed));
    this.hpk = await nacl.h2(this.commKey.publicKey);
    await this.storage.save('comm_key', this.commKey);
  }

  async commFromSecKey(rawSecretKey: Uint8Array): Promise<void> {
    if (!this.storage) {
      return;
    }
    const nacl = new NaCl();
    this.commKey = new Keys(await nacl.crypto_box_keypair_from_raw_sk(rawSecretKey));
    this.hpk = await nacl.h2(this.commKey.publicKey);
    await this.storage.save('comm_key', this.commKey);
  }

  private async loadGuestKeys() {
    if (!this.storage) {
      return;
    }
    const guestKeys = await this.storage.get('guest_registry');
    if (Array.isArray(guestKeys)) {
      this.guestKeys = new Map(guestKeys);
    }
  }

  async addGuest(guestTag: string, b64_pk: string): Promise<string> {
    return await this.processGuest(guestTag, b64_pk);
  }

  async addTempGuest(guestTag: string, b64_pk: string): Promise<string> {
    return await this.processGuest(guestTag, b64_pk, true);
  }

  async removeGuest(guestTag: string): Promise<boolean> {
    if (this.guestKeys.has(guestTag)) {
      this.guestKeys.delete(guestTag);
      await this.saveGuests();
    }
    return true;
  }

  private async processGuest(guestTag: string, b64_pk: string, isTemporary?: boolean): Promise<string> {
    const nacl = new NaCl();
    const b64_h2 = Utils.toBase64(Utils.decode_latin1(await nacl.h2(b64_pk)));
    this.guestKeys.set(guestTag, {
      pk: b64_pk,
      hpk: b64_h2,
      temp: !!isTemporary
    });
    if (isTemporary) {
      this.setKeyTimeout(guestTag);
      await this.saveGuests();
    }
    return b64_h2;
  }

  private setKeyTimeout(guestTag: string) {
    const existingTimeout = this.guestKeyTimeouts.get(guestTag);
    if (existingTimeout) {
      window.clearTimeout(existingTimeout.timeoutId);
    }

    const newTimeoutId = window.setTimeout(() => {
      this.guestKeys.delete(guestTag);
      this.guestKeyTimeouts.delete(guestTag);
    }, config.RELAY_SESSION_TIMEOUT);

    this.guestKeyTimeouts.set(guestTag, {
      timeoutId: newTimeoutId,
      startTime: Date.now()
    });
  }

  private async saveGuests() {
    if (!this.storage) {
      return;
    }
    await this.storage.save('guest_registry', Array.from(this.guestKeys.entries()));
  }

  private async getKey(tag: string) {
    if (!this.storage) {
      return;
    }
    const key = await this.storage.get(tag);
    if (typeof key === 'string') {
      return new Keys(key);
    } else {
      return null;
    }
  }
}

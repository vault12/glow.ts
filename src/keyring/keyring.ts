import { CryptoStorage } from '../crypto-storage/crypto-storage';
import { StorageDriver } from '../crypto-storage/storage-driver.interface';
import { LocalStorageDriver } from '../crypto-storage/local-storage.driver';
import { Keys } from '../keys/keys';
import { NaCl } from '../nacl/nacl';
import { Utils, Base64 } from '../utils/utils';
import { config } from '../config';
import { NaClDriver } from '../nacl/nacl-driver.interface';

interface KeyRecord {
  pk: Base64;
  hpk: Base64;
  temp: boolean;
}

interface TempKeyTimeout {
  // setTimeout has different return values in Node and browser,
  // so we extract it right from the environment
  timeoutId: ReturnType<typeof setTimeout>;
  startTime: number;
}

interface KeyRingBackup {
  [key: string]: string | null | undefined
}

// Manages the set of public keys of counterparties
export class KeyRing {
  static readonly commKeyTag = 'comm_key';
  static readonly guestRegistryTag = 'guest_registry';

  private cryptoStorage?: CryptoStorage;
  private commKey?: Keys;
  private hpk?: Uint8Array;
  private guestKeys: Map<string, KeyRecord> = new Map();
  private guestKeyTimeouts: Map<string, TempKeyTimeout> = new Map();
  private nacl: NaClDriver;

  private constructor(naclDriver: NaClDriver) {
    this.nacl = naclDriver;
  }

  static async new(id: string, storageDriver?: StorageDriver): Promise<KeyRing> {
    const nacl = NaCl.getInstance();
    const keyRing = new KeyRing(nacl);
    keyRing.cryptoStorage = await CryptoStorage.new(storageDriver || new LocalStorageDriver(), id);
    await keyRing.loadCommKey();
    await keyRing.loadGuestKeys();
    return keyRing;
  }

  static async fromBackup(id: string, backup: string, storageDriver?: StorageDriver): Promise<KeyRing> {
    const backupObject = JSON.parse(backup);
    const secretKey = Utils.fromBase64(backupObject[config.COMM_KEY_TAG]);
    delete backupObject[config.COMM_KEY_TAG];
    const restoredKeyRing = await KeyRing.new(id, storageDriver);
    restoredKeyRing.setCommFromSecKey(secretKey);
    for (const [key, value] of Object.entries(backupObject)) {
      await restoredKeyRing.addGuest(key, value as string);
    }
    return restoredKeyRing;
  }

  get storage(): CryptoStorage {
    if (!this.cryptoStorage) {
      throw new Error('No CryptoStorage set');
    }
    return this.cryptoStorage;
  }

  getNumberOfGuests(): number {
    return this.guestKeys.size;
  }

  getPubCommKey(): string | undefined {
    return this.commKey?.publicKey;
  }

  getHpk(): string | undefined {
    return this.hpk ? Utils.toBase64(this.hpk) : undefined;
  }

  getTagByHpk(hpk: string): string | null {
    for (const [key, value] of this.guestKeys) {
      if (value.hpk === hpk) {
        return key;
      }
    }
    return null;
  }

  getGuestKey(guestTag: string): Base64 | null {
    const keyRecord = this.guestKeys.get(guestTag);
    if (keyRecord) {
      return keyRecord.pk;
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
    const commKey = await this.getKey(KeyRing.commKeyTag);
    if (commKey) {
      this.commKey = commKey;
      this.hpk = await this.nacl.h2(this.commKey.publicKey);
    } else {
      const keypair = await this.nacl.crypto_box_keypair();
      this.commKey = new Keys(keypair);
      this.hpk = await this.nacl.h2(this.commKey.publicKey);
      await this.storage.save(KeyRing.commKeyTag, this.commKey);
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

  async setCommFromSeed(seed: Uint8Array): Promise<void> {
    this.commKey = new Keys(await this.nacl.crypto_box_keypair_from_seed(seed));
    this.hpk = await this.nacl.h2(this.commKey.publicKey);
    await this.storage.save(KeyRing.commKeyTag, this.commKey);
  }

  async setCommFromSecKey(rawSecretKey: Uint8Array): Promise<void> {
    this.commKey = new Keys(await this.nacl.crypto_box_keypair_from_raw_sk(rawSecretKey));
    this.hpk = await this.nacl.h2(this.commKey.publicKey);
    await this.storage.save(KeyRing.commKeyTag, this.commKey);
  }

  private async loadGuestKeys() {
    const guestKeys = await this.storage.get(KeyRing.guestRegistryTag);
    if (!guestKeys) {
      return;
    } else if (Array.isArray(guestKeys)) {
      this.guestKeys = new Map(guestKeys);
    } else {
      throw new Error('"Guest keys" is not an array');
    }
  }

  async addGuest(guestTag: string, publicKey: Base64): Promise<string> {
    return await this.processGuest(guestTag, publicKey);
  }

  async addTempGuest(guestTag: string, publicKey: Base64): Promise<string> {
    return await this.processGuest(guestTag, publicKey, true);
  }

  async removeGuest(guestTag: string): Promise<boolean> {
    if (this.guestKeys.has(guestTag)) {
      this.guestKeys.delete(guestTag);
      await this.saveGuests();
    }
    return true;
  }

  private async processGuest(guestTag: string, publicKey: Base64, isTemporary?: boolean): Promise<string> {
    const b64_h2 = Utils.toBase64(await this.nacl.h2(publicKey));
    this.guestKeys.set(guestTag, {
      pk: publicKey,
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
      clearTimeout(existingTimeout.timeoutId);
    }

    const newTimeoutId = setTimeout(() => {
      this.guestKeys.delete(guestTag);
      this.guestKeyTimeouts.delete(guestTag);
    }, config.RELAY_SESSION_TIMEOUT);

    this.guestKeyTimeouts.set(guestTag, {
      timeoutId: newTimeoutId,
      startTime: Date.now()
    });
  }

  private async saveGuests() {
    await this.storage.save(KeyRing.guestRegistryTag, Array.from(this.guestKeys.entries()));
  }

  private async getKey(tag: string) {
    const key = await this.storage.get(tag);
    if (typeof key === 'string') {
      return new Keys(key);
    } else {
      return null;
    }
  }
}

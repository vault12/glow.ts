import { CryptoStorage } from '../crypto-storage/crypto-storage';
import { StorageDriver } from '../crypto-storage/storage-driver.interface';
import { LocalStorageDriver } from '../crypto-storage/local-storage.driver';
import { Keys } from '../keys/keys';
import { NaCl } from '../nacl/nacl';
import { Utils, Base64 } from '../utils/utils';
import { NaClDriver } from '../nacl/nacl-driver.interface';

interface KeyRecord {
  pk: Base64;
  hpk: Base64;
}

const commKeyTag = '__::commKey::__';

interface KeyRingBackup {
  [commKeyTag]: string;
  [key: string]: string | null | undefined
}

// Manages the set of public keys of counterparties
export class KeyRing {
  static readonly commKeyTag = 'comm_key';
  static readonly guestRegistryTag = 'guest_registry';

  private commKey: Keys;
  private storage: CryptoStorage;
  private guestKeys: Map<string, KeyRecord> = new Map();
  private nacl: NaClDriver;

  private constructor(naclDriver: NaClDriver, cryptoStorage: CryptoStorage, commKey: Keys) {
    this.nacl = naclDriver;
    this.storage = cryptoStorage;
    this.commKey = commKey;
  }

  static async new(id: string, storageDriver?: StorageDriver): Promise<KeyRing> {
    const nacl = NaCl.getInstance();
    const cryptoStorage = await CryptoStorage.new(storageDriver || new LocalStorageDriver(), id);
    const commKey = await KeyRing.getCommKey(nacl, cryptoStorage);
    const keyRing = new KeyRing(nacl, cryptoStorage, commKey);

    await cryptoStorage.save(KeyRing.commKeyTag, commKey);
    await keyRing.loadGuestKeys();
    return keyRing;
  }

  static async fromBackup(id: string, backupString: string, storageDriver?: StorageDriver): Promise<KeyRing> {
    const backup: KeyRingBackup = JSON.parse(backupString);
    const secretKey = Utils.fromBase64(backup[commKeyTag]);
    const restoredKeyRing = await KeyRing.new(id, storageDriver);
    await restoredKeyRing.setCommFromSecKey(secretKey);
    for (const [key, value] of Object.entries(backup)) {
      if (key !== commKeyTag) {
        await restoredKeyRing.addGuest(key, value as string);
      }
    }
    return restoredKeyRing;
  }

  getNumberOfGuests(): number {
    return this.guestKeys.size;
  }

  getPubCommKey(): string {
    return this.commKey.publicKey;
  }

  getPrivateCommKey(): string {
    return this.commKey.privateKey;
  }

  async getHpk(): Promise<Base64> {
    const hpk = await this.nacl.h2(Utils.fromBase64(this.commKey.publicKey));
    return Utils.toBase64(hpk);
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

  // Backups

  async backup(): Promise<string> {
    const backup: KeyRingBackup = {
      [commKeyTag]: this.commKey.privateKey
    };

    if (this.getNumberOfGuests() > 0) {
      for (const [key, value] of this.guestKeys) {
        if (key && value) {
          backup[key] = value.pk;
        }
      }
    }
    return JSON.stringify(backup);
  }

  async setCommFromSeed(seed: Uint8Array): Promise<void> {
    this.commKey = new Keys(await this.nacl.crypto_box_keypair_from_seed(seed));
    await this.storage.save(KeyRing.commKeyTag, this.commKey);
  }

  async setCommFromSecKey(rawSecretKey: Uint8Array): Promise<void> {
    this.commKey = new Keys(await this.nacl.crypto_box_keypair_from_raw_sk(rawSecretKey));
    await this.storage.save(KeyRing.commKeyTag, this.commKey);
  }

  async addGuest(guestTag: string, publicKey: Base64): Promise<string> {
    const b64_h2 = Utils.toBase64(await this.nacl.h2(Utils.fromBase64(publicKey)));
    this.guestKeys.set(guestTag, {
      pk: publicKey,
      hpk: b64_h2
    });
    await this.saveGuests();
    return b64_h2;
  }

  async removeGuest(guestTag: string): Promise<boolean> {
    if (this.guestKeys.has(guestTag)) {
      this.guestKeys.delete(guestTag);
      await this.saveGuests();
    }
    return true;
  }

  private async loadGuestKeys() {
    const guestKeys = await this.storage.get(KeyRing.guestRegistryTag);
    if (!guestKeys) {
      return;
    } else if (Array.isArray(guestKeys)) {
      this.guestKeys = new Map(guestKeys);
    } else {
      throw new Error('[Keyring] Guest keys is not an array');
    }
  }

  private async saveGuests() {
    await this.storage.save(KeyRing.guestRegistryTag, Array.from(this.guestKeys.entries()));
  }

  private static async getCommKey(nacl: NaClDriver, storage: CryptoStorage): Promise<Keys> {
    const commKey = await storage.get(KeyRing.commKeyTag);
    if (commKey && typeof commKey === 'string') {
      return new Keys(commKey);
    } else {
      const keypair = await nacl.crypto_box_keypair();
      return new Keys(keypair);
    }
  }
}

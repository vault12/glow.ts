import { CryptoStorage } from '../crypto-storage/crypto-storage';
import { LocalStorageDriver } from '../crypto-storage/local-storage.driver';
import { Keys } from '../keys/keys';
import { Nacl } from '../nacl/nacl';
import { Utils, Base64 } from '../utils/utils';
import { config } from '../config';

interface KeyRecord {
  pk: Base64;
  hpk: Base64;
  temp: boolean;
}

interface KeyRingBackup {
  [key: string]: string | undefined
}

// Manages the set of public keys of counterparties
export class KeyRing {
  public storage: CryptoStorage;
  public commKey?: Keys;
  public hpk?: Uint8Array;
  public guestKeys: Map<string, KeyRecord>;
  public guestKeyTimeouts?: any; // TODO: define type

  private constructor() {
    this.storage = new CryptoStorage(new LocalStorageDriver());
    this.guestKeys = new Map();
  }

  static async new(): Promise<KeyRing> {
    const keyRing = new KeyRing();
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

  private async loadCommKey() {
    const nacl = new Nacl();
    const commKey = await this.getKey('comm_key');
    if (commKey) {
      this.commKey = commKey;
      this.hpk = nacl.h2(this.commKey.publicKey);
    } else {
      const keypair = nacl.crypto_box_keypair();
      this.commKey = new Keys(keypair);
      this.hpk = nacl.h2(this.commKey.publicKey);
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
    const nacl = new Nacl();
    this.commKey = new Keys(nacl.crypto_box_keypair_from_seed(seed));
    this.hpk = nacl.h2(this.commKey.publicKey);
    await this.storage.save('comm_key', this.commKey);
  }

  async commFromSecKey(rawSecretKey: Uint8Array): Promise<void> {
    const nacl = new Nacl();
    this.commKey = new Keys(nacl.crypto_box_keypair_from_raw_sk(rawSecretKey));
    this.hpk = nacl.h2(this.commKey.publicKey);
    await this.storage.save('comm_key', this.commKey);
  }

  private async loadGuestKeys() {
    const guestKeys = await this.storage.get('guest_registry');
    if (Array.isArray(guestKeys)) {
      this.guestKeys = new Map(guestKeys);
    }
    this.guestKeyTimeouts = {};
  }

  async addGuest(guestTag: string, b64_pk: string): Promise<string> {
    const b64_h2 = await this.addGuestRecord(guestTag, b64_pk);
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

  private async addGuestRecord(guestTag: string, b64_pk: string): Promise<string> {
    const nacl = new Nacl();
    const b64_h2 = Utils.toBase64(Utils.decode_latin1(nacl.h2(b64_pk)));
    this.guestKeys.set(guestTag, {
      pk: b64_pk,
      hpk: b64_h2,
      temp: false
    });
    return b64_h2;
  }

  private async saveGuests() {
    await this.storage.save('guest_registry', Array.from(this.guestKeys.entries()));
  }

  private async saveKey(tag: string, key: Keys) {
    await this.storage.save(tag, key.toString());
  }

  private async getKey(tag: string) {
    const key = await this.storage.get(tag);
    if (typeof key === 'string') {
      return new Keys(key);
    } else {
      return null;
    }
  }

  private async deleteKey(tag: string) {
    await this.storage.remove(tag);
  }
}

import { CryptoStorage } from '../crypto-storage/crypto-storage';
import { LocalStorageDriver } from '../crypto-storage/local-storage.driver';
import { Keys } from '../keys/keys';
import { Nacl } from '../nacl/nacl';
import { Utils, Base64 } from '../utils/utils';

interface KeyRecord {
  pk: Base64;
  hpk: Base64;
  temp: boolean;
}

// Manages the set of public keys of counterparties
export class KeyRing {
  public storage: CryptoStorage;
  public commKey?: Keys;
  public hpk?: Uint8Array;
  public guestKeys?: any; // TODO: define type
  public guestKeyTimeouts?: any; // TODO: define type

  constructor() {
    this.storage = new CryptoStorage(new LocalStorageDriver());
    this.loadCommKey();
    this.loadGuestKeys();
  }

  getNumberOfGuests(): number {
    return Object.keys(this.guestKeys || {}).length;
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

  private async loadGuestKeys() {
    const guestKeys = await this.storage.get('guest_registry');
    if (guestKeys) {
      this.guestKeys = guestKeys; // tag -> { pk, hpk }
    } else {
      this.guestKeys = {};
    }
    this.guestKeyTimeouts = {};
  }

  async addGuest(guestTag: string, b64_pk: string): Promise<string> {
    const b64_h2 = await this.addGuestRecord(guestTag, b64_pk);
    await this.saveGuests();
    return b64_h2;
  }

  async removeGuest(guestTag: string): Promise<boolean> {
    if (this.guestKeys[guestTag]) {
      delete this.guestKeys[guestTag];
      await this.saveGuests();
    }
    return true;
  }

  private async addGuestRecord(guestTag: string, b64_pk: string): Promise<string> {
    const nacl = new Nacl();
    const b64_h2 = Utils.toBase64(Utils.decode_latin1(nacl.h2(b64_pk)));
    this.guestKeys[guestTag] = {
      pk: b64_pk,
      hpk: b64_h2,
      temp: false
    } as KeyRecord;
    return b64_h2;
  }

  private async saveGuests() {
    await this.storage.save('guest_registry', this.guestKeys);
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

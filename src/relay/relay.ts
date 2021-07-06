import axios, { AxiosError, AxiosRequestConfig } from 'axios';

import { NaCl } from '../nacl/nacl';
import { NaClDriver, EncryptedMessage } from '../nacl/nacl-driver.interface';
import { EncryptionHelper } from '../nacl/encryption.helper';
import { config } from '../config';
import { Base64, Utils } from '../utils/utils';
import { Keys } from '../keys/keys';
import { RelayCommand } from '../zax.interface';

export interface RelayConnectionData {
  h2Signature: Uint8Array;
  relayPublicKey: Uint8Array;
}

/**
 * Low-level operations with Zax relay
 */
export class Relay {
  private nacl: NaClDriver;
  private difficulty = 0;
  private publicKey?: Uint8Array;
  private clientToken?: Uint8Array;
  private sessionKeys?: Keys;
  private tokenExpirationTimeoutHandle?: ReturnType<typeof setTimeout>;
  private sessionExpirationTimeoutHandle?: ReturnType<typeof setTimeout>;

  constructor(public url: string) {
    this.nacl = NaCl.getInstance();
  }

  get isConnected() {
    // relay is assumed to be connected when it got session keys and server public
    // sessionKeys are not permanent so relay won't be connected when sessionKeys will be removed within timeout
    return !!(this.sessionKeys && this.publicKey);
  }

  // ---------- Connection initialization ----------

  /**
   * Exchanges tokens with a relay and gets a temp session key for this relay.
   * Returns h₂(signature) and a relay public key
   */
  async openConnection(): Promise<RelayConnectionData> {
    this.sessionKeys = new Keys(await this.nacl.crypto_box_keypair());
    this.clientToken = await this.nacl.random_bytes(config.RELAY_TOKEN_LEN);
    const relayToken = await this.fetchRelayToken();
    this.publicKey = await this.fetchRelayPublicKey(relayToken);
    return {
      h2Signature: await this.getSignature(relayToken, this.sessionKeys),
      relayPublicKey: this.publicKey
    };
  }

  /**
   * Sends a client token to a relay and saves a relay token
   */
  private async fetchRelayToken(): Promise<Uint8Array> {
    if (!this.clientToken) {
      throw new Error('[Relay] clientToken is required please openConnection first');
    }
    const data = await this.httpCall('start_session', Utils.toBase64(this.clientToken));
    // Set a timer to mark a relay instance as having an expired token after a certain time
    this.scheduleTokenExpiration();
    // Relay responds with its own counter token. Until session is established these 2 tokens are handshake id.
    const [token, difficulty] = this.parseResponse('start_session', data);

    this.difficulty = parseInt(difficulty, 10);
    if (this.difficulty > 10) {
      console.log(`[Relay] ${this.url} requested difficulty ${this.difficulty}. Session handshake may take longer.`);
    }

    return Utils.fromBase64(token);
  }

  /**
   * Completes the handshake and saves a relay pubic key
   */
  private async fetchRelayPublicKey(relayToken: Uint8Array) {
    if (!this.clientToken) {
      throw new Error('[Relay] clientToken is required please openConnection first');
    }
    // After clientToken is sent to the relay, we use only h2() of it
    const h2ClientToken = Utils.toBase64(await this.nacl.h2(this.clientToken));

    const handshake = new Uint8Array([...this.clientToken, ...relayToken]);
    let sessionHandshake: Uint8Array;

    // Compute session handshake based on difficulty level set by the server
    if (this.difficulty === 0) {
      sessionHandshake = await this.nacl.h2(handshake);
    } else {
      sessionHandshake = await this.ensureNonceDifficulty(handshake);
    }

    // We confirm handshake by sending back h2(clientToken, relay_token)
    const relayPk = await this.httpCall('verify_session', h2ClientToken, Utils.toBase64(sessionHandshake));
    // Relay gives us back temp session key masked by clientToken we started with
    return Utils.fromBase64(relayPk);
  }

  /**
   * Attaches a mailbox and fetches number of messages
   */
  async prove(payload: EncryptedMessage): Promise<string> {
    if (!this.clientToken) {
      throw new Error('[Relay] clientToken is required please openConnection first');
    }
    if (!this.sessionKeys) {
      throw new Error('[Relay] No session key found, open the connection first');
    }
    const h2ClientToken = Utils.toBase64(await this.nacl.h2(this.clientToken));
    const result = await this.httpCall('prove',
      h2ClientToken, this.sessionKeys.publicKey, payload.nonce, payload.ctext);
    this.scheduleSessionExpiration();
    return result;
  }

  async encodeMessage(message: string): Promise<EncryptedMessage> {
    if (!this.publicKey) {
      throw new Error('[Relay] No relay public key found, open the connection first');
    }
    if (!this.sessionKeys) {
      throw new Error('[Relay] No session key found, open the connection first');
    }

    return await EncryptionHelper.encodeMessage(
      await this.nacl.encode_utf8(message), this.publicKey, Utils.fromBase64(this.sessionKeys?.privateKey));
  }

  async decodeMessage(nonce: Base64, ctext: Base64): Promise<any> {
    const relayPk = this.publicKey;
    if (!relayPk) {
      throw new Error('[Relay] No relay public key found, open the connection first');
    }
    if (!this.sessionKeys) {
      throw new Error('[Relay] No session key found, open the connection first');
    }

    const decodedData = await EncryptionHelper.decodeMessage(Utils.fromBase64(nonce), Utils.fromBase64(ctext), relayPk,
      Utils.fromBase64(this.sessionKeys.privateKey));
    if (decodedData === null) {
      throw new Error('[Relay] failed to decode message');
    }
    return JSON.parse(decodedData);
  }

  // ---------- Low-level server request handling ----------

  /**
   * Executes a message/file command on a relay, parses and validates the response
   */
  async runCmd(command: RelayCommand, hpk: Base64, message: EncryptedMessage, ctext?: string): Promise<string[]> {
    if (!Object.keys(RelayCommand).includes(command)) {
      throw new Error(`[Relay] ${this.url} doesn't support command ${command}`);
    }

    const payload = [hpk, message.nonce, message.ctext];
    // if we are sending symmetrically encrypted ctext, it goes on the next line in the payload
    if (ctext) {
      payload.push(ctext);
    }

    let response: string;
    try {
      response = await this.httpCall('command', ...payload);
    } catch (err: any) {
      if ((err as AxiosError).isAxiosError &&  (err as AxiosError<any>).response?.status === 401) {
        // clear session if unauthorized
        this.clearSession();
        this.clearToken();
      }
      throw err;
    }
    return this.parseResponse(command, response);
  }

  private async getSignature(relayToken: Uint8Array, sessionKeys: Keys) {
    if (!this.clientToken) {
      throw new Error('[Relay] clientToken is required please openConnection first');
    }
    const clientTempPk = Utils.fromBase64(sessionKeys.publicKey);
    // Alice creates a 32 byte session signature as h₂(a_temp_pk, relayToken, clientToken)
    const signature = new Uint8Array([...clientTempPk, ...relayToken, ...this.clientToken]);
    const h2Signature = await this.nacl.h2(signature);
    return h2Signature;
  }

  /**
   * Executes a call to a relay and return raw string response
   */
  private async httpCall(command: string, ...params: string[]): Promise<string> {
    const requestPayload: AxiosRequestConfig = {
      url: `${this.url}/${command}`,
      method: 'post',
      headers: {
        'Accept': 'text/plain',
        'Content-Type': 'text/plain'
      },
      data: params.join('\r\n'),
      responseType: 'text',
      timeout: config.RELAY_AJAX_TIMEOUT
    };

    // NOTE: Network and server errors are not handled ny Glow itself.
    // They should instead be handled where the library is used
    const response = await axios(requestPayload);
    return String(response.data);
  }

  /**
   * Parses relay response and throws an error if its format is unexpected
   */
  private parseResponse(command: string, rawResponse: string): string[] {
    const response = rawResponse.split('\r\n');

    if (!rawResponse || !this.validateResponse(command, response.length)) {
      console.log(response);
      throw new Error(`[Relay] ${this.url} - ${command}: Bad response`);
    }

    return response;
  }

  /**
   * Compares the expected number of lines in response with what was actually received from a relay
   */
  private validateResponse(command: string, lines: number): boolean {
    switch (command) {
      case RelayCommand.upload:
      case RelayCommand.messageStatus:
      case RelayCommand.delete:
        return lines === 1;
      case RelayCommand.downloadFileChunk:
        return lines === 3;
      default:
        return lines === 2;
    }
  }

  /**
   * delete token locally before it was removed on server so will reconnect without getting unauthorized error
   */
  private scheduleTokenExpiration() {
    if (this.tokenExpirationTimeoutHandle) {
      clearTimeout(this.tokenExpirationTimeoutHandle);
    }
    this.tokenExpirationTimeoutHandle = setTimeout(() => this.clearToken(), config.RELAY_TOKEN_TIMEOUT);
  }

  private clearToken() {
    if (this.tokenExpirationTimeoutHandle) {
      clearTimeout(this.tokenExpirationTimeoutHandle);
    }
    if (this.clientToken) {
      delete this.clientToken;
    }
  }

  /**
   * established session is valid only for some period need to remove it after it's ttl
   * so relay will reconnect without receiving error from server
   */
  private scheduleSessionExpiration() {
    if (this.sessionExpirationTimeoutHandle) {
      clearTimeout(this.sessionExpirationTimeoutHandle);
    }
    this.sessionExpirationTimeoutHandle = setTimeout(() => {
      this.clearSession();
    }, config.RELAY_SESSION_TIMEOUT);
  }

  private clearSession() {
    if (this.sessionExpirationTimeoutHandle) {
      clearTimeout(this.sessionExpirationTimeoutHandle);
    }
    if (this.sessionKeys) {
      delete this.sessionKeys;
    }
  }

  // ---------- Difficulty adjustment ----------

  /**
   * Continuously calculates the nonce until one requested by a relay is found
   */
  private async ensureNonceDifficulty(handshake: Uint8Array) {
    let nonce;
    let h2;
    do {
      nonce = await this.nacl.random_bytes(32);
      h2 = await this.nacl.h2(new Uint8Array([...handshake, ...nonce]));
    } while (!this.arrayZeroBits(h2));

    return nonce;
  }

  /**
   * Returns `true` if the rightmost n bits of a byte are 0.
   * Check whether the rightmost difficulty bits of an Uint8Array are 0, where
   * the lowest indexes of the array represent those rightmost bits. Thus if
   * the difficulty is 17, then array[0] and array[1] should be 0, as should the
   * rightmost bit of array[2]. This is used for our difficulty settings in Zax to
   * reduce burden on a busy server by ensuring clients have to do some
   * additional work during the session handshake
   */
  private arrayZeroBits(array: Uint8Array): boolean {
    let byte;
    let n = this.difficulty;
    for (let i = 0; i <= (1 + this.difficulty / 8); i++) {
      byte = array[i];
      if (n <= 0) {
        return true;
      }
      if (n > 8) {
        n -= 8;
        if (byte > 0) {
          return false;
        }
      } else {
        return this.firstZeroBits(byte, n);
      }
    }
    return false;
  }

  /**
   * Returns `true` if the rightmost n bits of a byte are 0
   */
  private firstZeroBits(byte: number, n: number): boolean {
    return byte === ((byte >> n) << n);
  }
}

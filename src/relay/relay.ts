import axios, { AxiosRequestConfig } from 'axios';

import { NaCl } from '../nacl/nacl';
import { NaClDriver, EncryptedMessage } from '../nacl/nacl-driver.interface';
import { config } from '../config';
import { Base64, Utils } from '../utils/utils';
import { Keys } from '../keys/keys';

/**
 * Low-level operations with Zax relay
 */
export class Relay {
  // Plugins can add their own commands to specific relays
  static readonly relayCommands = [
    // Message commands
    'count', 'upload', 'download', 'messageStatus', 'delete',
    // File commands
    'startFileUpload', 'uploadFileChunk', 'downloadFileChunk', 'fileStatus', 'deleteFile'];

  private nacl: NaClDriver;
  private difficulty: number;
  public relayToken?: Uint8Array;
  public publicKey?: string;

  private constructor(public url: string, public clientToken: Uint8Array, public sessionKeys: Keys) {
    this.nacl = NaCl.getInstance();
    this.difficulty = 0;
  }

  static async new(url: string): Promise<Relay> {
    const nacl = NaCl.getInstance();
    // Generate a client token. It will be used as part of handshake id with relay
    const clientToken = await nacl.random_bytes(config.RELAY_TOKEN_LEN);
    // Generate and store a pair of keys required to start a relay session.
    // Each session with each Zax relay creates its own temporary session keys
    const sessionKeys = new Keys(await nacl.crypto_box_keypair());
    return new Relay(url, clientToken, sessionKeys);
  }

  // ---------- Connection initialization ----------

  /**
   * Exchanges tokens with a relay and gets a temp session key for this relay
   */
  async openConnection(): Promise<void> {
    await this.fetchRelayToken();
    await this.fetchRelayPublicKey();
  }

  /**
   * Sends a client token to a relay and saves a relay token
   */
  private async fetchRelayToken(): Promise<void> {
    const data = await this.httpCall('start_session', Utils.toBase64(this.clientToken));

    // Relay responds with its own counter token. Until session is established these 2 tokens are handshake id.
    const [token, difficulty] = this.parseResponse('start_session', data);
    this.relayToken = Utils.fromBase64(token);
    this.difficulty = parseInt(difficulty, 10);

    if (this.difficulty > 10) {
      console.log(`[Relay] ${this.url} requested difficulty ${this.difficulty}. Session handshake may take longer.`);
    }
  }

  /**
   * Completes the handshake and saves a relay pubic key
   */
  private async fetchRelayPublicKey(): Promise<void> {
    if (!this.relayToken) {
      throw new Error('[Relay] No relay token found, fetch it from the relay first');
    }
    // After clientToken is sent to the relay, we use only h2() of it
    const h2ClientToken = Utils.toBase64(await this.nacl.h2(this.clientToken));

    const handshake = new Uint8Array([...this.clientToken, ...this.relayToken]);
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
    this.publicKey = relayPk;
  }

  /**
   * Returns an ID for a relay (for encryption purposes)
   */
  relayId(): string {
    return `relay_#${this.url}`;
  }

  /**
   * Attaches a mailbox and fetches number of messages
   */
  async prove(payload: EncryptedMessage, publicKey: string): Promise<string> {
    const h2ClientToken = Utils.toBase64(await this.nacl.h2(this.clientToken));
    return await this.httpCall('prove', h2ClientToken, publicKey, payload.nonce, payload.ctext);
  }

  /* eslint-disable @typescript-eslint/explicit-module-boundary-types, @typescript-eslint/no-explicit-any */
  async encodeMessage(message: any): Promise<EncryptedMessage> {
    const relayPk = this.publicKey;
    if (!relayPk) {
      throw new Error('[Relay] No relay public key found, open the connection first');
    }

    const privateKey = this.sessionKeys.privateKey;

    if (!(message instanceof Uint8Array)) {
      message = await this.nacl.encode_utf8(JSON.stringify(message));
    }

    return await this.nacl.rawEncodeMessage(message, Utils.fromBase64(relayPk), Utils.fromBase64(privateKey));
  }

  /* eslint-disable @typescript-eslint/no-explicit-any */
  async decodeMessage(nonce: Base64, ctext: Base64): Promise<any> {
    const relayPk = this.publicKey;
    if (!relayPk) {
      throw new Error('[Relay] No relay public key found, open the connection first');
    }

    const privateKey = this.sessionKeys.privateKey;

    return await this.nacl.rawDecodeMessage(Utils.fromBase64(nonce), Utils.fromBase64(ctext),
      Utils.fromBase64(relayPk), Utils.fromBase64(privateKey));
  }

  // ---------- Low-level server request handling ----------

  /**
   * Executes a message/file command on a relay, parses and validates the response
   */
  async runCmd(command: string, hpk: Base64, message: EncryptedMessage, ctext?: string): Promise<string[]> {
    if (!Relay.relayCommands.includes(command)) {
      throw new Error(`[Relay] ${this.url} doesn't support command ${command}`);
    }

    const payload = [hpk, message.nonce, message.ctext];
    // if we are sending symmetrically encrypted ctext, it goes on the next line in the payload
    if (ctext) {
      payload.push(ctext);
    }

    const response = await this.httpCall('command', ...payload);
    return this.parseResponse(command, response);
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

    const response = await axios(requestPayload);
    return String(response.data);
  }

  /**
   * Parses relay response and throws an error if its format is unexpected
   */
  private parseResponse(command: string, rawResponse: string): string[] {
    const response = rawResponse.split('\r\n');

    if (!rawResponse || !this.validateResponse(command, response.length)) {
      throw new Error(`[Relay] ${this.url} - ${command}: Bad response`);
    }

    return response;
  }

  /**
   * Compares the expected number of lines in response with what was actually received from a relay
   */
  private validateResponse(command: string, lines: number): boolean {
    switch (command) {
      case 'upload':
      case 'messageStatus':
      case 'delete':
        return lines === 1;
      case 'downloadFileChunk':
        return lines === 3;
      default:
        return lines === 2;
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
    } while (!this.arrayZeroBits(h2, this.difficulty));

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
  private arrayZeroBits(array: Uint8Array, difficulty: number): boolean {
    let byte;
    let n = difficulty;
    for (let i = 0; i <= (1 + difficulty / 8); i++) {
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

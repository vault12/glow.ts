import axios, { AxiosRequestConfig } from 'axios';
import { Mutex } from 'async-mutex';

import { NaCl } from '../nacl/nacl';
import { NaClDriver, EncryptedMessage } from '../nacl/nacl-driver.interface';
import { config } from '../config';
import { Base64, Utils } from '../utils/utils';
import { Keys } from '../keys/keys';

export interface ConnectionData {
  h2Signature: Uint8Array;
  relayPublicKey: Uint8Array;
}

// In the future versions, plugins could add their own commands to specific relays
enum RelayCommand {
  // Zax message commands
  count = 'count',
  upload = 'upload',
  download = 'download',
  messageStatus = 'messageStatus',
  delete = 'delete',
  // Zax file commands
  startFileUpload = 'startFileUpload',
  uploadFileChunk = 'uploadFileChunk',
  downloadFileChunk = 'downloadFileChunk',
  fileStatus = 'fileStatus',
  deleteFile = 'deleteFile'
}

/**
 * Low-level operations with Zax relay
 */
export class Relay {
  private nacl: NaClDriver;
  private difficulty = 0;
  private publicKey?: Uint8Array;

  // Static global dictionary of relays to refer to, because the apps using this library
  // only need a single instance of a Relay class per given URL.
  private static relays: { [url: string]: Relay } = {};
  // Ensures that a call to the static getInstance() method is blocking
  private static instanceMutex = new Mutex();

  private constructor(public url: string, private clientToken: Uint8Array, private sessionKeys: Keys) {
    this.nacl = NaCl.getInstance();
  }

  private static async new(url: string): Promise<Relay> {
    const nacl = NaCl.getInstance();
    // Generate a client token. It will be used as part of handshake id with relay
    const clientToken = await nacl.random_bytes(config.RELAY_TOKEN_LEN);
    // Generate and store a pair of keys required to start a relay session.
    // Each session with each Zax relay creates its own temporary session keys
    const sessionKeys = new Keys(await nacl.crypto_box_keypair());
    return new Relay(url, clientToken, sessionKeys);
  }

  /**
   * Relay factory, that returns a Relay instance for a given URL,
   * or creates a new one if it hasn't yet been initialized.
   * The usage of `async-mutex` guarantees that only one instance per given URL will ever exist.
   */
  static async getInstance(url: string): Promise<Relay> {
    return await this.instanceMutex.runExclusive(async () => {
      let relay = this.relays[url];
      if (!relay) {
        relay = this.relays[url] = await Relay.new(url);
      }
      return relay;
    });
  }

  // ---------- Connection initialization ----------

  /**
   * Exchanges tokens with a relay and gets a temp session key for this relay.
   * Returns h₂(signature) and a relay public key
   */
  async openConnection(): Promise<ConnectionData> {
    const relayToken = await this.fetchRelayToken();
    const relayPublicKey = await this.fetchRelayPublicKey(relayToken);
    return {
      h2Signature: await this.getSignature(relayToken),
      relayPublicKey
    };
  }

  /**
   * Sends a client token to a relay and saves a relay token
   */
  private async fetchRelayToken(): Promise<Uint8Array> {
    const data = await this.httpCall('start_session', Utils.toBase64(this.clientToken));

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
  private async fetchRelayPublicKey(relayToken: Uint8Array): Promise<Uint8Array> {
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
    this.publicKey = Utils.fromBase64(relayPk);
    return this.publicKey;
  }

  /**
   * Attaches a mailbox and fetches number of messages
   */
  async prove(payload: EncryptedMessage): Promise<string> {
    const h2ClientToken = Utils.toBase64(await this.nacl.h2(this.clientToken));
    return await this.httpCall('prove', h2ClientToken, this.sessionKeys.publicKey, payload.nonce, payload.ctext);
  }

  async encodeMessage(message: any): Promise<EncryptedMessage> {
    const relayPk = this.publicKey;
    if (!relayPk) {
      throw new Error('[Relay] No relay public key found, open the connection first');
    }

    const privateKey = this.sessionKeys.privateKey;

    if (!(message instanceof Uint8Array)) {
      message = await this.nacl.encode_utf8(JSON.stringify(message));
    }

    return await this.nacl.rawEncodeMessage(message, relayPk, Utils.fromBase64(privateKey));
  }

  async decodeMessage(nonce: Base64, ctext: Base64): Promise<any> {
    const relayPk = this.publicKey;
    if (!relayPk) {
      throw new Error('[Relay] No relay public key found, open the connection first');
    }

    const privateKey = this.sessionKeys.privateKey;

    return await this.nacl.rawDecodeMessage(Utils.fromBase64(nonce), Utils.fromBase64(ctext), relayPk,
      Utils.fromBase64(privateKey));
  }

  // ---------- Low-level server request handling ----------

  /**
   * Executes a message/file command on a relay, parses and validates the response
   */
  async runCmd(command: string, hpk: Base64, message: EncryptedMessage, ctext?: string): Promise<string[]> {
    if (!Object.keys(RelayCommand).includes(command)) {
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

  private async getSignature(relayToken: Uint8Array) {
    const clientTempPk = Utils.fromBase64(this.sessionKeys.publicKey);
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

    try {
      const response = await axios(requestPayload);
      return String(response.data);
    } catch (e) {
      console.log(e.response);
      throw new Error('[Relay] Bad Response');
    }
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

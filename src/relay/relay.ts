import axios, { AxiosRequestConfig } from 'axios';

import { NaCl } from '../nacl/nacl';
import { NaClDriver } from '../nacl/nacl-driver.interface';
import { config } from '../config';
import { Base64, Utils } from '../utils/utils';
import { Mailbox } from '../mailbox/mailbox';

export interface EncryptedMessage {
  nonce: Base64;
  ctext: Base64;
}

/**
 * Low-level operations with Zax relay
 */
export class Relay {
  // Plugins can add their own commands to specific relays
  static readonly relayCommands = [
    // Message commands
    'count', 'upload', 'download', 'messageStatus', 'delete',
    // File commands
    'startFileUpload', 'uploadFileChunk', 'downloadFileChunk', 'fileStatus', 'deleteFile',
    // Reserved for future use
    'getEntropy'];

  private nacl: NaClDriver;
  private diff: number;
  private clientToken?: Uint8Array;
  private relayToken?: Uint8Array;
  private relayPublicKey?: Base64;

  constructor(public url: string) {
    this.nacl = NaCl.getInstance();
    this.diff = 0;
  }

  // ------------------------------ Connection initialization ------------------------------

  /**
   * Exchanges tokens with a relay and gets a temp session key for this relay
   */
  async openConnection(): Promise<void> {
    await this.getRelayToken();
    await this.getRelayKey();
  }

  /**
   * Sends a client token to a relay and saves a relay token
   */
  private async getRelayToken(): Promise<void> {
    // Generate a client token. It will be used as part of handshake id with relay
    if (!this.clientToken) {
      this.clientToken = await this.nacl.random_bytes(config.RELAY_TOKEN_LEN);
    }

    const data = await this.httpCall('start_session', Utils.toBase64(this.clientToken));

    // Relay responds with its own counter token. Until session is established these 2 tokens are handshake id.
    const [token, diff] = this.parseResponse('start_session', data);
    this.relayToken = Utils.fromBase64(token);
    this.diff = parseInt(diff, 10);

    if (this.diff > 10) {
      console.log(`[Relay] ${this.url} requested difficulty ${this.diff}. Session handshake may take longer.`);
    }
  }

  /**
   * Completes the handshake and saves a relay pubic key
   */
  async getRelayKey(): Promise<void> {
    if (!this.clientToken || !this.relayToken) {
      throw new Error('[Relay] No tokens found, fetch them from the relay first');
    }
    // After clientToken is sent to the relay, we use only h2() of it
    const h2ClientToken = Utils.toBase64(await this.nacl.h2(this.clientToken));

    const handshake = new Uint8Array([...this.clientToken, ...this.relayToken]);
    let sessionHandshake: Uint8Array;

    // Compute session handshake based on difficulty level set by the server
    if (this.diff === 0) {
      sessionHandshake = await this.nacl.h2(handshake);
    } else {
      sessionHandshake = await this.ensureNonceDiff(handshake);
    }

    // We confirm handshake by sending back h2(clientToken, relay_token)
    const relayPk = await this.httpCall('verify_session', h2ClientToken, Utils.toBase64(sessionHandshake));
    // Relay gives us back temp session key masked by clientToken we started with
    this.relayPublicKey = relayPk;
  }

  /**
   * Returns an ID for a relay (for encryption purposes)
   */
  relayId(): string {
    return `relay_#${this.url}`;
  }

  /**
   * Adds a relay to mailbox keyring and fetches number of messages
   */
  async connectMailbox(mbx: Mailbox): Promise<number> {
    if (!this.relayPublicKey || !this.clientToken || !this.relayToken) {
      throw new Error('[Relay] No tokens found, run openConnection() first');
    }

    const key = await mbx.createSessionKey(this.relayId(), true);
    const clientTempPk = Utils.fromBase64(key.publicKey);

    await mbx.keyRing.addTempGuest(this.relayId(), this.relayPublicKey);
    // Now it belongs to the mailbox
    delete this.relayPublicKey;

    //  Alice creates a 32 byte session signature as h₂(a_temp_pk, relayToken, clientToken)
    const signature = new Uint8Array([...clientTempPk, ...this.relayToken, ...this.clientToken]);
    const h2Signature = await this.nacl.h2(signature);
    const encryptedSignature = await mbx.encodeMessage(this.relayId(), h2Signature);

    const payload = {
      pub_key: mbx.keyRing.getPubCommKey(),
      nonce: encryptedSignature.nonce,
      ctext: encryptedSignature.ctext
    };
    const outer = await mbx.encodeMessage(this.relayId(), payload, true);
    const h2ClientToken = Utils.toBase64(await this.nacl.h2(this.clientToken));
    const messagesNumber = await this.httpCall('prove', h2ClientToken, Utils.toBase64(clientTempPk),
      outer.nonce, outer.ctext);
    return parseInt(messagesNumber, 10);
  }

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

  // ------------------------------ Low-level server request handling ------------------------------

  /**
   * Executes a call to a relay and return raw string response
   */
  private async httpCall(command: string, ...params: string[]): Promise<string> {
    axios.defaults.adapter = require('axios/lib/adapters/http');

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
    let response = rawResponse.split('\r\n');
    if (response.length < 2) {
      response = rawResponse.split('\n');
    }

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

  // -------------------------------- Difficulty adjustment --------------------------------

  /**
   * Continuously calculates the nonce until one requested by a relay is found
   */
  private async ensureNonceDiff(handshake: Uint8Array) {
    let nonce;
    let h2;
    do {
      nonce = await this.nacl.random_bytes(32);
      h2 = await this.nacl.h2(new Uint8Array([...handshake, ...nonce]));
    } while (!this.arrayZeroBits(h2, this.diff));

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

import axios, { AxiosRequestConfig } from 'axios';

import { NaCl } from '../nacl/nacl';
import { NaClDriver } from '../nacl/nacl-driver.interface';
import { config } from '../config';
import { Base64, Utils } from '../utils/utils';
import { Mailbox } from '../mailbox/mailbox';

/**
 * Low-level operations with Zax relay.
 */
export class Relay {
  // plugins can add their own commands to specific relays
  static readonly relayCommands = [
    //message commands
    'count', 'upload', 'download', 'messageStatus', 'delete',
    // file commands
    'startFileUpload', 'uploadFileChunk', 'downloadFileChunk', 'fileStatus', 'deleteFile',
    // reserved for future use
    'getEntropy'];

  private nacl: NaClDriver;
  private clientToken?: Uint8Array;
  private relayToken?: Uint8Array;
  private diff: number;
  private relayPublicKey?: string;

  constructor(public url: string) {
    this.nacl = NaCl.getInstance();
    this.diff = 0;
  }

  // ------------------------------ Connection initialization ------------------------------

  // exchange tokens with a relay and get a temp session key for this relay
  async openConnection(): Promise<void> {
    await this.getServerToken();
    await this.getServerKey();
  }

  private async getServerToken(): Promise<void> {
    // Generate a client token. It will be used as part of handshake id with relay
    if (!this.clientToken) {
      this.clientToken = await this.nacl.random_bytes(config.RELAY_TOKEN_LEN);
    }
    // sanity check the client token
    if (this.clientToken.length !== config.RELAY_TOKEN_LEN) {
      throw new Error(`[Relay] Client token must be ${config.RELAY_TOKEN_LEN} bytes`);
    }

    const data = await this.sendRequest('start_session', Utils.toBase64(this.clientToken));
    if (!data) {
      throw new Error(`[Relay] ${this.url} - start_session error; empty response`);
    }

    // Relay responds with its own counter token. Until session is established these 2 tokens are handshake id.
    const lines = this.splitString(data);
    this.relayToken = Utils.fromBase64(lines[0]);
    if (lines.length !== 2) {
      throw new Error(`Wrong start_session from ${this.url}`);
    }
    this.diff = parseInt(lines[1], 10);

    if (this.diff > 10) {
      console.log(`Relay ${this.url} requested difficulty ${this.diff}. Session handshake may take longer.`);
    }
  }

  async getServerKey(): Promise<void> {
    if (!this.clientToken || !this.relayToken) {
      throw new Error('No token');
    }
    const clientTokenString = Utils.decode_latin1(this.clientToken);
    // After clientToken is sent to the relay, we use only h2() of it
    const h2ClientToken = Utils.toBase64(await this.nacl.h2(clientTokenString));
    const handshake = new Uint8Array([...this.clientToken, ...this.relayToken]);

    let sessionHandshake: Uint8Array;

    if (this.diff === 0) {
      sessionHandshake = await this.nacl.h2(Utils.decode_latin1(handshake));
    } else {
      sessionHandshake = await this.ensureNonceDiff(handshake);
    }

    // relay gives us back temp session key masked by clientToken we started with
    const relayPk = await this.sendRequest('verify_session', h2ClientToken, Utils.toBase64(sessionHandshake));
    this.relayPublicKey = relayPk;
  }

  relayId(): string {
    return `relay_#${this.url}`;
  }

  async connectMailbox(mbx: Mailbox): Promise<string> {
    const key = await mbx.createSessionKey(this.relayId(), true);
    if (!this.relayPublicKey) {
      throw new Error('No relay public key');
    }
    const clientTempPk = Utils.fromBase64(key.publicKey);

    await mbx.keyRing?.addTempGuest(this.relayId(), this.relayPublicKey);
    delete this.relayPublicKey;
    if (!this.clientToken || !this.relayToken) {
      throw new Error('No token');
    }

    //  Alice creates a 32 byte session signature as h₂(a_temp_pk, relayToken, clientToken)
    const signature = new Uint8Array([...clientTempPk, ...this.relayToken, ...this.clientToken]);

    const h2Signature = await this.nacl.h2(Utils.decode_latin1(signature));
    const inner = await mbx.encodeMessage(this.relayId(), h2Signature);
    const payload = {
      pub_key: mbx.keyRing?.getPubCommKey(),
      nonce: Utils.toBase64(inner.nonce),
      ctext: Utils.toBase64(inner.ctext)
    };

    const outer = await mbx.encodeMessage(this.relayId(), payload, true);
    const clientTokenString = Utils.decode_latin1(this.clientToken);
    const h2ClientToken = Utils.toBase64(await this.nacl.h2(clientTokenString));
    await this.sendRequest('prove', h2ClientToken, Utils.toBase64(clientTempPk),
      Utils.toBase64(outer.nonce), Utils.toBase64(outer.ctext));
    return this.relayId();
  }

  // ------------------------------ Relay commands public API ------------------------------

  async upload(mailbox: Mailbox, toHpk: Uint8Array, payload: any) {
    const token = await this.runCmd('upload', mailbox, {
      to: Utils.toBase64(toHpk),
      payload: {
        nonce: Utils.toBase64(payload.nonce),
        ctext: Utils.toBase64(payload.ctext),
      }
    });
    return {
      token,
      nonce: Utils.toBase64(payload.nonce),
      ctext: Utils.toBase64(payload.ctext)
    };
  }

  async count(mailbox: Mailbox) {
    return await this.runCmd('count', mailbox);
  }

  async download(mailbox: Mailbox) {
    return await this.runCmd('download', mailbox);
  }

  async delete(mailbox: Mailbox, nonceList: any): Promise<number> {
    return await this.runCmd('delete', mailbox, { payload: nonceList });
  }

  async messageStatus(mailbox: Mailbox, storageToken: Base64): Promise<number> {
    return await this.runCmd('messageStatus', mailbox, { token: storageToken });
  }

  async startFileUpload(mailbox: Mailbox, toHpk: Uint8Array, fileSize: number, metadata: any) {
    return await this.runCmd('startFileUpload', mailbox, {
      to: Utils.toBase64(toHpk),
      file_size: fileSize,
      metadata: metadata
    });
  }

  async uploadFileChunk(mailbox: Mailbox, uploadID: string, part: number, totalParts: number, fileData: any) {
    return await this.runCmd('uploadFileChunk', mailbox, {
      uploadID,
      part,
      last_chunk: (totalParts - 1 === part),
      nonce: fileData.nonce,
      ctext: fileData.ctext
    });
  }

  async downloadFileChunk(mailbox: Mailbox, uploadID: string, part: number) {
    return await this.runCmd('downloadFileChunk', mailbox, {
      uploadID,
      part
    });
  }

  async fileStatus(mailbox: Mailbox, uploadID: string) {
    return await this.runCmd('fileStatus', mailbox, { uploadID });
  }

  async deleteFile(mailbox: Mailbox, uploadID: string) {
    return await this.runCmd('deleteFile', mailbox, { uploadID });
  }

  // ------------------------------ Low-level server request handling ------------------------------

  private async runCmd(command: string, mailbox: Mailbox, params?: any) {
    if (!Relay.relayCommands.includes(command)) {
      throw new Error(`Relay ${this.url} doesn't support command ${command}`);
    }

    params = { cmd: command, ...params };

    let ctext;
    const mbxHpk = mailbox.getHpk();
    if (!mbxHpk) {
      throw new Error('No hpk');
    }
    if (command === 'uploadFileChunk') {
      ctext = params.ctext;
      delete params.ctext;
    }
    const message = await mailbox.encodeMessage(this.relayId(), params, true);
    let response;
    if (command === 'uploadFileChunk') {
      response = await this.sendRequest('command', mbxHpk,
        Utils.toBase64(message.nonce), Utils.toBase64(message.ctext), ctext);
    } else {
      response = await this.sendRequest('command', mbxHpk,
        Utils.toBase64(message.nonce), Utils.toBase64(message.ctext));
    }

    if (!response) {
      throw new Error(`${this.url} - ${command} error; empty response`);
    }

    return await this.processResponse(response, mailbox, command, params);
  }

  private async sendRequest(type: string, ...params: string[]): Promise<string> {
    let request;

    switch (type) {
      case 'start_session':
        request = await this.httpCall('start_session', ...params);
        break;
      case 'verify_session':
        request = await this.httpCall('verify_session', ...params);
        break;
      case 'prove':
        request = await this.httpCall('prove', ...params);
        break;
      case 'command':
        request = await this.httpCall('command', ...params);
        break;
      default:
        throw new Error(`Unknown request type: ${type}`);
    }
    return request;
  }

  private async httpCall(command: string, ...data: string[]): Promise<string> {
    axios.defaults.adapter = require('axios/lib/adapters/http');

    const requestPayload: AxiosRequestConfig = {
      url: `${this.url}/${command}`,
      method: 'post',
      headers: {
        'Accept': 'text/plain',
        'Content-Type': 'text/plain'
      },
      data: data.join('\r\n'),
      responseType: 'text',
      timeout: config.RELAY_AJAX_TIMEOUT
    };

    const response = await axios(requestPayload);
    return String(response.data);
  }

  private splitString(rawResponse: string): string[] {
    let response = [];
    response = rawResponse.split('\r\n');
    if (response.length < 2) {
      response = rawResponse.split('\n');
    }
    return response;
  }

  private async processResponse(rawResponse: string, mailbox: Mailbox, command: string, params: any) {
    const response = this.splitString(String(rawResponse));

    if (command === 'delete') {
      return JSON.parse(rawResponse);
    }

    if (command === 'upload') {
      if (response.length !== 1 || response[0].length !== config.RELAY_TOKEN_B64) {
        throw new Error(`${this.url} - ${command}: Bad response`);
      }
      return rawResponse;
    }

    if (command === 'messageStatus') {
      if (response.length !== 1) {
        throw new Error(`${this.url} - ${command}: Bad response`);
      }
      return parseInt(response[0], 10);
    }

    if (command === 'downloadFileChunk') {
      if (response.length !== 3) {
        throw new Error(`${this.url} - ${command}: Bad response`);
      }
      const nonce = response[0];
      const ctext = response[1];
      const decoded = await mailbox.decodeMessage(this.relayId(),
        Utils.fromBase64(nonce), Utils.fromBase64(ctext), true);
      decoded.ctext = response[2];
      return decoded;
    }

    if (response.length !== 2) {
      throw new Error(`${this.url} - ${command}: Bad response`);
    }

    const nonce = response[0];
    const ctext = response[1];
    const decoded = await mailbox.decodeMessage(this.relayId(),
      Utils.fromBase64(nonce), Utils.fromBase64(ctext), true);
    return decoded;
  }

  // -------------------------------- Difficulty adjustment --------------------------------

  private async ensureNonceDiff(handshake: Uint8Array) {
    let nonce;
    let h2;
    do {
      nonce = await this.nacl.random_bytes(32);
      h2 = await this.nacl.h2(Utils.decode_latin1(new Uint8Array([...handshake, ...nonce])));
    } while(!this.arrayZeroBits(h2, this.diff));

    return nonce;
  }

  // check whether the rightmost difficulty bits of an Uint8Array are 0, where
  // the lowest indexes of the array represent those rightmost bits. Thus if
  // the difficulty is 17, then array[0] and array[1] should be 0, as should the
  // rightmost bit of array[2]. This is used for our difficulty settings in Zax to
  // reduce burden on a busy server by ensuring clients have to do some
  // additional work during the session handshake
  private arrayZeroBits(array: Uint8Array, difficulty: number) {
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

  // returns `true` if the rightmost n bits of a byte are 0
  private firstZeroBits(byte: number, n: number): boolean {
    return byte === ((byte >> n) << n);
  }
}

import axios, { AxiosRequestConfig } from 'axios';

import { NaCl } from '../nacl/nacl';
import { NaClDriver } from '../nacl/nacl-driver.interface';
import { config } from '../config';
import { Utils } from '../utils/utils';
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
  private diff?: number;
  private relayPublicKey?: string;

  constructor(public url: string) {
    this.nacl = NaCl.getInstance();
  }

  async openConnection(): Promise<void> {
    // exchange tokens with a relay and get a temp session key for this relay
    await this.getServerToken();
    await this.getServerKey();
  }

  async getServerToken(): Promise<boolean> {
    // Generate a clientToken. It will be used as part of handshake id with relay
    if (!this.clientToken) {
      this.clientToken = await this.nacl.random_bytes(config.RELAY_TOKEN_LEN);
    }
    // sanity check the client token
    if (this.clientToken && this.clientToken.length !== config.RELAY_TOKEN_LEN) {
      throw new Error(`Token must be ${config.RELAY_TOKEN_LEN} bytes`);
    }

    const data = await this.httpRequest('start_session', Utils.toBase64(this.clientToken));
    if (!data) {
      throw new Error(`${this.url} - start_session error; empty response`);
    }

    // relay responds with its own counter token. Until session is
    // established these 2 tokens are handshake id.
    const lines = this.processData(data);
    this.relayToken = Utils.fromBase64(lines[0]);
    if (lines.length !== 2) {
      throw new Error(`Wrong start_session from ${this.url}`);
    }
    this.diff = parseInt(lines[1], 10);

    if (this.diff > 10) {
      console.log(`Relay ${this.url} requested difficulty ${this.diff}. Session handshake may take longer.`);
    }

    return true;
  }

  async getServerKey() {
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
    const relayPk = await this.httpRequest('verify_session', h2ClientToken, Utils.toBase64(sessionHandshake));
    this.relayPublicKey = relayPk;
  }

  relayId() {
    return `relay_#${this.url}`;
  }

  async runCmd(command: string, mailbox: Mailbox, params?: any) {
    if (!Relay.relayCommands.includes(command)) {
      throw new Error(`Relay ${this.url} doesn't support command ${command}`);
    }

    const data = { cmd: command, ...params };

    const response = await this.httpRequest('command', mailbox, data);
    if (!response) {
      throw new Error(`${this.url} - ${command} error; empty response`);
    }

    return await this.processResponse(response, mailbox, command, params);
  }

  async connectMailbox(mbx: Mailbox) {
    const key = await mbx.createSessionKey(this.relayId(), true);
    await this.httpRequest('prove', mbx, key?.publicKey);
    return this.relayId();
  }

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

  async delete(mailbox: Mailbox, nonceList: any) {
    return await this.runCmd('delete', mailbox, { payload: nonceList });
  }

  async messageStatus(mailbox: Mailbox, storageToken: any) {
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

  async fileStatus(mailbox: Mailbox, uploadID: string) {
    return await this.runCmd('fileStatus', mailbox, { uploadID });
  }

  private async ensureNonceDiff(handshake: Uint8Array) {
    let nonce;
    let h2;
    do {
      nonce = await this.nacl.random_bytes(32);
      h2 = await this.nacl.h2(Utils.decode_latin1(new Uint8Array([...handshake, ...nonce])));
    } while(!this.arrayZeroBits(h2, this.diff));

    return nonce;
  }

  private async httpRequest(type: string, ...params: any[]) {
    let request;
    let mbx: Mailbox;
    switch (type) {
      case 'start_session':
        request = await this.httpCall('start_session', params[0]);
        break;
      case 'verify_session':
        request = await this.httpCall('verify_session', params[0], params[1]);
        break;
      case 'prove':
        if (!this.relayPublicKey) {
          throw new Error('No relay public key');
        }
        mbx = params[0];
        const clientTempPk = Utils.fromBase64(params[1]);

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

        await this.httpCall('prove', h2ClientToken, Utils.toBase64(clientTempPk),
          Utils.toBase64(outer.nonce), Utils.toBase64(outer.ctext));
        break;
      case 'command':
        mbx = params[0];
        const mbxHpk = mbx.getHpk();
        if (!mbxHpk) {
          throw new Error('No hpk');
        }
        const message = await mbx.encodeMessage(this.relayId(), params[1], true);
        request = await this.httpCall('command', mbxHpk,
          Utils.toBase64(message.nonce), Utils.toBase64(message.ctext));
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

  private processData(rawResponse: string): string[] {
    let response = [];
    response = rawResponse.split('\r\n');
    if (response.length < 2) {
      response = rawResponse.split('\n');
    }
    return response;
  }

  private async processResponse(rawResponse: string, mailbox: Mailbox, command: string, params: any) {
    const response = this.processData(String(rawResponse));

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

    if (response.length !== 2) {
      throw new Error(`${this.url} - ${command}: Bad response`);
    }

    const nonce = response[0];
    const ctext = response[1];
    const decoded = await mailbox.decodeMessage(this.relayId(),
      Utils.fromBase64(nonce), Utils.fromBase64(ctext), true);
    return decoded;
  }

  private firstZeroBits(byte: any, n: any) {
    return byte === ((byte >> n) << n);
  }

  private arrayZeroBits(arr: any, diff: any) {
    let a, i, j, ref, rmd;
    rmd = diff;
    for (i = j = 0, ref = 1 + diff / 8; (0 <= ref ? j <= ref : j >= ref); i = 0 <= ref ? ++j : --j) {
      a = arr[i];
      if (rmd <= 0) {
        return true;
      }
      if (rmd > 8) {
        rmd -= 8;
        if (a > 0) {
          return false;
        }
      } else {
        return this.firstZeroBits(a, rmd);
      }
    }
    return false;
  }
}

import axios, { AxiosRequestConfig } from 'axios';

import { NaCl } from '../nacl/nacl';
import { NaClDriver } from '../nacl/nacl-driver.interface';
import { config } from '../config';
import { Utils } from '../utils/utils';
import { Mailbox } from '../mailbox/mailbox';
import { Keys } from '../keys/keys';

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
    console.log(relayPk);
    this.relayPublicKey = relayPk;
  }

  relayId() {
    return `relay_#${this.url}`;
  }

  runCmd(command: string, mailbox: any, params?: any) {
    if (!Relay.relayCommands.includes(command)) {
      throw new Error(`Relay ${this.url} doesn't support command ${command}`);
    }

    const data = { cmd: command, ...params };

    return this.httpRequest('command', mailbox, data).then(response => {
      if (!response) {
        throw new Error(`${this.url} - ${command} error; empty response`);
      }
      // this.processResponse(response, mailbox, command, params);
    });
  }

  async connectMailbox(mbx: Mailbox) {
    const key = await mbx.createSessionKey(this.relayId(), true);
    await this.httpRequest('prove', mbx, key?.publicKey);
    return this.relayId();
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
        const mbx: Mailbox = params[0];
        const clientTempPk = params[1];
        mbx.keyRing?.addTempGuest(this.relayId(), this.relayPublicKey);
        delete this.relayPublicKey;
      default:
        throw new Error(`Unknown request type: ${type}`);
    }
    return request;
  }

  private async httpCall(command: string, ...data: string[]): Promise<any> {
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
    return response.data;
  }

  private processData(rawResponse: string): string[] {
    let response = [];
    response = rawResponse.split('\r\n');
    if (response.length < 2) {
      response = rawResponse.split('\n');
    }
    return response;
  }

  // private processResponse(rawResponse: string, mailbox: any, command: string, params: any) {
  // }

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

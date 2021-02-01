import { Base64 } from './utils/utils';

/**
 * Interfaces of Zax relay command requests and responses.
 * See https://github.com/vault12/zax for details.
 *
 * Full technical specification:
 * https://s3-us-west-1.amazonaws.com/vault12/crypto_relay.pdf
 */


/**
 * Status of a previously sent message equals redis TTL.
 * See https://redis.io/commands/ttl.
 * -2 : missing key
 * -1 : key never expires
 * 0+ : key time to live in seconds
 */
export enum MessageStatusResponse {
  MissingKey = -2,
  NeverExpires = -1
}

// -------------- Message formats --------------

/**
 * Format of raw messages provided by `download` Zax command
 */
export interface ZaxRawMessage {
  data: string;
  time: number;
  from: Base64;
  nonce: Base64;
  kind: 'message' | 'file';
}

export interface ZaxTextMessage {
  /**
   * Decoded object after JSON.parse
   */
  data: any;
  time: number;
  senderTag: string;
  nonce: Base64;
  kind: 'message';
}

export interface ZaxFileMessage {
  data: FileUploadMetadata;
  time: number;
  senderTag: string;
  uploadID: string;
  nonce: Base64;
  kind: 'file';
}

export interface ZaxPlainMessage {
  data: string;
  time: number;
  from: Base64;
  nonce: Base64;
  kind: 'plain';
}

export type ParsedZaxMessage = ZaxPlainMessage | ZaxFileMessage | ZaxTextMessage;

// -------------- File command responses --------------
// See https://github.com/vault12/zax/wiki/Zax-2.0-File-Commands

export interface StartFileUploadResponse {
  uploadID: string;
  max_chunk_size: number;
  storage_token: string;
  skey: Uint8Array;
}

export interface UploadFileChunkResponse {
  status: 'OK' | 'NOT_FOUND';
}

export interface FileStatusResponse {
  status: 'COMPLETE' | 'UPLOADING' | 'START' | 'NOT_FOUND';
  total_chunks: number;
  file_size: number;
  bytes_stored: number;
}

export interface DeleteFileResponse {
  status: 'OK' | 'NOT_FOUND';
}

export interface FileUploadMetadata {
  name: string;
  orig_size: number;
  md5?: string;
  created?: number;
  modified?: number;
  attrs?: string;
  skey?: Base64;
}

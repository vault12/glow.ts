import { Relay } from './relay';
import { NaCl } from '../nacl/nacl';
import { Mailbox } from '../mailbox/mailbox';
import { randomNumber } from './tests.helper';
import fs from 'fs';

describe('Relay / File transfer', () => {
  let testRelay: Relay;
  let Alice: Mailbox;
  let Bob: Mailbox;

  let chunkSize: number;
  let numberOfChunks: number;
  let file: Buffer;
  let decodedFile: Uint8Array;

  let uploadID: string;
  let skey: Uint8Array;

  beforeAll(async () => {
    NaCl.setInstance();

    testRelay = new Relay('https://z2.vault12.com');
    Alice = await Mailbox.new('Alice');
    Bob = await Mailbox.new('Bob');
    const aliceKey = Alice.getPubCommKey();
    const bobKey = Bob.getPubCommKey();
    await Alice.keyRing.addGuest('Bob', bobKey);
    await Bob.keyRing.addGuest('Alice', aliceKey);

    file = fs.readFileSync('.test.zip');
    expect(file.length).toBe(765);

    // Arbitrary chunk size for testing purposes
    // NOTE: for big files `max_chunk_size` value of `startFileUpload` response should be considered
    chunkSize = randomNumber(50, 300);
    // Using Math.ceil here, because if file size is not evenly divisible
    // by `chunkSize`, then we have one more chunk
    numberOfChunks = Math.ceil(file.length / chunkSize);
  });

  it('start upload', async () => {
    const response = await Alice.startFileUpload('Bob', testRelay, {
      name: randomNumber(1, 100) + '.zip',
      orig_size: 765,
      created: randomNumber(1480000000, 1520000000),
      modified: randomNumber(1480000000, 1520000000)
    });

    expect(response).toHaveProperty('uploadID');
    expect(response).toHaveProperty('max_chunk_size');
    expect(response).toHaveProperty('storage_token');
    expect(response).toHaveProperty('skey');
    expect(typeof response.uploadID).toBe('string');
    uploadID = response.uploadID;
    skey = response.skey;
  });

  it('upload chunks', async () => {
    for (let i = 0; i < numberOfChunks; i++) {
      const chunk = new Uint8Array(file.slice(i * chunkSize, (i + 1) * chunkSize));
      const response = await Alice.uploadFileChunk(testRelay, uploadID, chunk, i, numberOfChunks, skey);
      expect(response).toHaveProperty('status');
      expect(response.status).toBe('OK');
    }
  });

  it('check file status and retrieve metadata', async () => {
    const statusAlice = await Alice.getFileStatus(testRelay, uploadID);
    expect(statusAlice.status).toBe('COMPLETE');
    await Bob.connectToRelay(testRelay);
    const statusBob = await Bob.getFileStatus(testRelay, uploadID);
    expect(statusBob.status).toBe('COMPLETE');

    const metadata = await Bob.getFileMetadata(testRelay, uploadID);
    expect(typeof metadata.skey).toBe('string');
    expect(metadata.orig_size).toBe(file.length);
    expect(metadata).toHaveProperty('name');
    expect(metadata).toHaveProperty('created');
    expect(metadata).toHaveProperty('modified');
  });

  it('download chunks', async () => {
    decodedFile = new Uint8Array(file.length);
    let downloadedBytes = 0;
    for (let i = 0; i < numberOfChunks; i++) {
      const chunk = await Bob.downloadFileChunk(testRelay, uploadID, i, skey);
      if (!chunk) {
        throw new Error('error dowloading chunk');
      }
      decodedFile.set(chunk, downloadedBytes);
      downloadedBytes += chunk.length;
    }
  });

  it('verify decoded file', async () => {
    expect(decodedFile).toEqual(new Uint8Array(file));
  });

  it('delete file', async () => {
    const response = await Bob.deleteFile(testRelay, uploadID);
    expect(response.status).toEqual('OK');
  });
});

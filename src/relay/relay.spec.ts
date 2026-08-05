import { Relay } from './relay';
import { NaCl } from '../nacl/nacl';
import { testRelayURL } from '../tests.helper';

describe('Relay', () => {
  beforeAll(async () => {
    NaCl.setDefaultInstance();
  });

  it('should initialize', async () => {
    const relay = new Relay(testRelayURL);
    const connection = await relay.openConnection();
    expect(connection.h2Signature).toHaveLength(32);
    expect(connection.relayPublicKey).toHaveLength(32);
  });

  it('should handle server errors', async () => {
    global.fetch = jest.fn().mockRejectedValue(new Error('500'));

    const relay = new Relay(testRelayURL);
    const connection = relay.openConnection();
    expect(connection).rejects.toThrow('500');
  });

  describe('relay rejections', () => {
    const rejection = (status: number, details?: string) => ({
      ok: false,
      status,
      headers: { get: (name: string) => (name.toLowerCase() === 'x-error-details' ? details ?? null : null) },
    });

    it('carries X-Error-Details from the relay on the thrown error', async () => {
      global.fetch = jest.fn().mockResolvedValue(rejection(400, 'Sender storage quota exceeded'));

      const relay = new Relay(testRelayURL);
      await expect(relay.openConnection()).rejects.toMatchObject({
        name: 'GlowNetworkError',
        status: 400,
        details: 'Sender storage quota exceeded',
        message: 'GlowNetworkError status: 400 (Sender storage quota exceeded)',
      });
    });

    it('keeps details undefined and the message unchanged when the header is absent', async () => {
      global.fetch = jest.fn().mockResolvedValue(rejection(429));

      const relay = new Relay(testRelayURL);
      await expect(relay.openConnection()).rejects.toMatchObject({
        name: 'GlowNetworkError',
        status: 429,
        details: undefined,
        message: 'GlowNetworkError status: 429',
      });
    });
  });
});

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
    const rejection = (status: number, details?: string, retryAfter?: string) => ({
      ok: false,
      status,
      headers: {
        get: (name: string) => {
          if (name.toLowerCase() === 'x-error-details') return details ?? null;
          if (name.toLowerCase() === 'retry-after') return retryAfter ?? null;
          return null;
        },
      },
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
        retryAfter: undefined,
        message: 'GlowNetworkError status: 429',
      });
    });

    it('carries Retry-After delta-seconds from the relay on the thrown error', async () => {
      global.fetch = jest.fn().mockResolvedValue(rejection(429, undefined, '61'));

      const relay = new Relay(testRelayURL);
      await expect(relay.openConnection()).rejects.toMatchObject({
        name: 'GlowNetworkError',
        status: 429,
        retryAfter: 61,
      });
    });

    it('carries a zero Retry-After as a valid value', async () => {
      global.fetch = jest.fn().mockResolvedValue(rejection(429, undefined, '0'));

      const relay = new Relay(testRelayURL);
      await expect(relay.openConnection()).rejects.toMatchObject({
        name: 'GlowNetworkError',
        status: 429,
        retryAfter: 0,
      });
    });

    it('ignores a Retry-After value that is not delta-seconds', async () => {
      global.fetch = jest.fn().mockResolvedValue(rejection(429, undefined, 'Wed, 21 Oct 2026 07:28:00 GMT'));

      const relay = new Relay(testRelayURL);
      await expect(relay.openConnection()).rejects.toMatchObject({
        name: 'GlowNetworkError',
        status: 429,
        retryAfter: undefined,
      });
    });

    it('ignores Retry-After spellings outside the decimal-integer form', async () => {
      for (const value of ['1.5', '1e3', '0x10', '-5']) {
        global.fetch = jest.fn().mockResolvedValue(rejection(429, undefined, value));

        const relay = new Relay(testRelayURL);
        await expect(relay.openConnection()).rejects.toMatchObject({
          name: 'GlowNetworkError',
          status: 429,
          retryAfter: undefined,
        });
      }
    });
  });
});

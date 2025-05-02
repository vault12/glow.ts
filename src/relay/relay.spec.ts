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
});

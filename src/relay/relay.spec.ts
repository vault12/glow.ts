import { Relay } from './relay';
import { NaCl } from '../nacl/nacl';
import { testRelayURL } from '../tests.helper';

describe('Relay', () => {
  beforeAll(async () => {
    NaCl.setInstance();
  });

  it('initialize', async () => {
    const testRelay = await Relay.new(testRelayURL);
    const connectionData = await testRelay.openConnection();
    expect(connectionData.h2Signature).toHaveLength(32);
    expect(connectionData.relayPublicKey).toHaveLength(32);
  });
});

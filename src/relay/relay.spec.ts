import { Relay } from './relay';
import { NaCl } from '../nacl/nacl';
import { testRelayURL } from '../tests.helper';

describe('Relay', () => {
  beforeAll(async () => {
    NaCl.setInstance();
  });

  it('initialize', async () => {
    const testRelay = new Relay(testRelayURL);
    await testRelay.openConnection();
    expect(testRelay.relayId()).toBe(`relay_#${testRelayURL}`);
  });
});

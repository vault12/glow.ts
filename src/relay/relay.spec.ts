import axios from 'axios';
import MockAdapter from 'axios-mock-adapter';

import { Relay } from './relay';
import { NaCl } from '../nacl/nacl';
import { testRelayURL } from '../tests.helper';
import { NaClDriver } from '../nacl/nacl-driver.interface';

describe('Relay', () => {
  let nacl: NaClDriver;
  beforeAll(async () => {
    NaCl.setInstance();
    nacl = NaCl.getInstance();
  });

  it('should initialize', async () => {
    const relay = new Relay(testRelayURL);
    const connection = await relay.openConnection();
    expect(connection.h2Signature).toHaveLength(32);
    expect(connection.relayPublicKey).toHaveLength(32);
  });

  it('should ever create only one instance for a given URL', async () => {
    const relay1 = new Relay(testRelayURL);
    const relay2 = new Relay(testRelayURL);
    // attempt to run both constructors simultaneously
    await Promise.all([relay1, relay2]);
    expect(relay1).toEqual(relay2);
  });

  it('should handle server errors', async () => {
    // This sets the mock adapter on the default Axios instance
    const mock = new MockAdapter(axios);
    // Always return 500 Internal Server Error
    mock.onPost().reply(500);

    const relay = new Relay(testRelayURL);
    const connection = relay.openConnection();
    expect(connection).rejects.toThrow('500');

    // Stop mocking Axios
    mock.restore();
  });
});

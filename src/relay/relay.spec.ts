import axios from 'axios';
import MockAdapter from 'axios-mock-adapter';

import { Relay } from './relay';
import { NaCl } from '../nacl/nacl';
import { testRelayURL } from '../tests.helper';

describe('Relay', () => {
  beforeAll(async () => {
    NaCl.setInstance();
  });

  it('should initialize', async () => {
    const relay = await Relay.getInstance(testRelayURL);
    const connection = await relay.openConnection();
    expect(connection.h2Signature).toHaveLength(32);
    expect(connection.relayPublicKey).toHaveLength(32);
  });

  it('should ever create only one instance for a given URL', async () => {
    const relay1 = Relay.getInstance(testRelayURL);
    const relay2 = Relay.getInstance(testRelayURL);
    // attempt to run both constructors simultaneously
    await Promise.all([relay1, relay2]);
    expect(relay1).toEqual(relay2);
  });

  it('should handle server errors', async () => {
    // Testing mode: suppress console log for a server error
    jest.spyOn(console, 'log').mockImplementation();
    // This sets the mock adapter on the default Axios instance
    const mock = new MockAdapter(axios);
    // Always return 500 Internal Server Error
    mock.onPost().reply(500);

    const relay = await Relay.getInstance(testRelayURL);
    const connection = relay.openConnection();
    expect(connection).rejects.toThrow(Error);

    // Stop mocking Axios
    mock.restore();
  });
});

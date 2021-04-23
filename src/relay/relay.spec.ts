import { Relay } from './relay';
import { NaCl } from '../nacl/nacl';
import { testRelayURL } from '../tests.helper';
import axios from 'axios';
import MockAdapter from 'axios-mock-adapter';

describe('Relay', () => {
  beforeAll(async () => {
    NaCl.setInstance();
  });

  it('initialize', async () => {
    const testRelay = await Relay.new(testRelayURL);
    const connection = await testRelay.openConnection();
    expect(connection.h2Signature).toHaveLength(32);
    expect(connection.relayPublicKey).toHaveLength(32);
  });

  it('handle server errors', async () => {
    // Testing mode: suppress console log for a server error
    jest.spyOn(console, 'log').mockImplementation();
    // This sets the mock adapter on the default Axios instance
    const mock = new MockAdapter(axios);
    // Always return 500 Internal Server Error
    mock.onPost().reply(500);

    const testRelay = await Relay.new(testRelayURL);
    const connection = testRelay.openConnection();
    expect(connection).rejects.toThrow(Error);

    // Stop mocking Axios
    mock.restore();
  });
});

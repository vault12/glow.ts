import { NaCl } from '../nacl/nacl';
import { testRelayURL, testRelayURL2 } from '../tests.helper';
import { RelayFactory } from './relay-factory';

describe('RelayFactory', () => {

  beforeAll(() => {
    NaCl.setInstance();
  });

  it('should ever create only one instance for same URLs', async () => {
    const factory = new RelayFactory();
    const relay1 = factory.getInstance(testRelayURL);
    const relay2 = factory.getInstance(testRelayURL);
    expect(relay1).toBe(relay2);
  });

  it('should ever create only different instances for different URLs', async () => {
    const factory = new RelayFactory();
    const relay1 = factory.getInstance(testRelayURL);
    const relay2 = factory.getInstance(testRelayURL2);
    expect(relay1).not.toBe(relay2);
  });
});
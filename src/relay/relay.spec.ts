import { Relay } from './relay';
import { NaCl } from '../nacl/nacl';

describe('Relay', () => {
  beforeAll(async () => {
    NaCl.setInstance();
  });

  it('initialize', async () => {
    const testRelay = new Relay('https://z2.vault12.com');
    await testRelay.openConnection();
    expect(testRelay.relayId()).toBe('relay_#https://z2.vault12.com');
  });
});

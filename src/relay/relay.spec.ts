import { Relay } from './relay';
import { NaCl } from '../nacl/nacl';

describe('Relay', () => {
  let testRelay: Relay;

  beforeEach(() => {
    NaCl.setInstance();
    testRelay = new Relay('https://z2.vault12.com');
  });

  it('should init', async () => {
    await testRelay.openConnection();
  });
});

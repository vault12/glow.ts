import { Mailbox } from './mailbox';
import { NaCl } from '../nacl/nacl';

describe('Mailbox', () => {
  let testMailbox: Mailbox;

  beforeEach(async () => {
    NaCl.setInstance();
    testMailbox = await Mailbox.new('Alice');
  });

  it('should get hpk', async () => {
    await testMailbox.getHpk();
  });
});

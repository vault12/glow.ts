import { Relay } from './relay';
import { Mutex } from 'async-mutex';

export class RelaysService {
  private static relays: {[url: string]: Relay} = {};
  private static relayMutex = new Mutex();

  /**
   * Returns a Relay instance for given URL, or creates a new one if wasn't initialized
   */
  static async getRelay(url: string): Promise<Relay> {
    return await this.relayMutex.runExclusive(async () => {
      let relay = this.relays[url];
      if (!relay) {
        relay = this.relays[url] = await Relay.new(url);
      }
      return relay;
    });
  }
}

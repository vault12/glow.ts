import { Relay } from './relay';

export class RelaysService {
  private static relays: {[url: string]: Relay} = {};

  /**
   * Returns a Relay instance for given URL, or creates a new one if wasn't initialized
   */
  static async getRelay(url: string): Promise<Relay> {
    let relay = this.relays[url];
    if (!relay) {
      relay = this.relays[url] = await Relay.new(url);
    }
    return relay;
  }
}

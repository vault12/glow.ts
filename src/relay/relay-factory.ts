import { Relay } from './relay';

export class RelayFactory {

  private relays: { [url: string]: Relay } = {};

  /**
   * Relay factory, that returns a Relay instance for a given URL,
   * or creates a new one if it hasn't yet been initialized.
   */
  getInstance(url: string) {
    let relay = this.relays[url];
    if (!relay) {
      relay = this.relays[url] = new Relay(url);
    }
    return relay;
  }
}
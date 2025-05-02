import { webcrypto } from 'node:crypto';
import JSDOMEnvironment from 'jest-environment-jsdom';

export default class JSDOMPolyfillsEnvironment extends JSDOMEnvironment {
  constructor(...args: ConstructorParameters<typeof JSDOMEnvironment>) {
    super(...args);

    // adopted from https://github.com/jsdom/jsdom/issues/1724#issuecomment-1446858041
    this.global.fetch = fetch;
    this.global.Headers = Headers;
    this.global.Request = Request;
    this.global.Response = Response;

    // addopded from https://github.com/jsdom/jsdom/issues/1612#issuecomment-1723498282
    Object.defineProperty(this.global, 'crypto', { value: webcrypto });
  }
}

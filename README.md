# glow.ts
Client library for interacting with Zax Cryptographic Relay

## Running tests

Unit tests are powered by [Jest](https://jestjs.io). The engine runs all the tests in each `describe` section serially in the order they are described in the `.spec.ts` file.
By default, unit tests connect to a remote [Zax](https://github.com/vault12/zax) Cryptographic Relay Server on `https://z.vault12.com`.
You may also run tests on a local or any other test server by modifying the code in [src/tests.helper.ts#L1](src/tests.helper.ts#L1).

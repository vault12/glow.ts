# glow.ts

<p align="center">
  <img src="https://user-images.githubusercontent.com/1370944/122228957-056d6f00-cec1-11eb-82a1-03dc85e89d83.jpg"
    alt="Glow">
</p>

<p align="center">
  <a href="https://github.com/vault12/glow.ts/actions/workflows/ci.yml">
    <img src="https://github.com/vault12/glow.ts/actions/workflows/ci.yml/badge.svg" alt="Github Actions Build Status" />
  </a>
  <a href="https://npmjs.com/package/glow.ts">
    <img src="https://img.shields.io/npm/v/glow.ts" alt="NPM Package" />
  </a>
  <a href="https://opensource.org/licenses/MIT">
    <img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="MIT License" />
  </a>
</p>

<p align="center">
  <a href="http://makeapullrequest.com">
    <img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg" alt="PRs welcome" />
  </a>
  <a href="https://twitter.com/_Vault12_">
    <img src="https://img.shields.io/twitter/follow/_Vault12_?label=Follow&style=social" alt="Follow" />
  </a>
</p>

![Coverage total](https://raw.githubusercontent.com/vault12/glow.ts/badges/badges/coverage-total.svg)

**Glow.ts** is a client library for interacting with [Zax Cryptographic Relay](https://github.com/vault12/zax), a [NaCl-based Cryptographic Relay](https://s3-us-west-1.amazonaws.com/vault12/zax_infogfx.jpg). This reference implementation is written in TypeScript. The original deprecated implementation in CoffeeScript can be [found there](https://github.com/vault12/glow).

## Installation

Glow can be easily installed via `npm`, which is included when you install [Node.js](https://nodejs.org/).
In a terminal, navigate to the directory in which you'd like to install Glow and type the following:
```Shell
npm install glow.ts
```
The built version of Glow will be available in `node_modules/glow.ts/dist` subdirectory, packaged as both
CommonJS and ESM library.

## Dashboard app

**Glow.ts** powers a test [Dashboard app](https://github.com/vault12/zax-dashboard) to provide a user-friendly access point to encrypted Mailboxes on a given relay.

We maintain a live [Test Server](https://zt.vault12.com) that runs the stable build of Zax Dashboard. For testing purposes expiration of any communication on that relay is set to *30 minutes*.

You can also check the latest build of `master` branch on [Github Pages](https://vault12.github.io/zax-dashboard/).

## Running tests

Unit tests are powered by [Jest](https://jestjs.io). The engine runs all the tests in each `describe` section serially in the order they are described in the `.spec.ts` file.
By default, unit tests connect to a remote [Zax](https://github.com/vault12/zax) Cryptographic Relay Server on `https://z.vault12.com`.
You may also run tests on a local or any other test server by modifying the code in the [tests helper](src/tests.helper.ts#L1).

## Ecosystem

Project | Description
--- | ---
[Zax](https://github.com/vault12/zax) | NaCl-based Cryptographic Relay
[Zax Dashboard](https://github.com/vault12/zax-dashboard) | Sample dashboard app for Zax Cryptographic Relay
[TrueEntropy](https://github.com/vault12/TrueEntropy) | High volume thermal entropy generator

## License

Glow is released under the [MIT License](http://opensource.org/licenses/MIT).

## Legal Reminder

Exporting/importing and/or use of strong cryptography software, providing cryptography hooks, or even just communicating technical details about cryptography software is illegal in some parts of the world. If you import this software to your country, re-distribute it from there or even just email technical suggestions or provide source patches to the authors or other people you are strongly advised to pay close attention to any laws or regulations which apply to you. The authors of this software are not liable for any violations you make - it is your responsibility to be aware of and comply with any laws or regulations which apply to you.
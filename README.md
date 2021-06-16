# glow.ts

<p align="center">
  <img src="https://user-images.githubusercontent.com/1370944/122228957-056d6f00-cec1-11eb-82a1-03dc85e89d83.jpg"
    alt="Glow">
</p>

<p align="center">
  <a href="https://travis-ci.com/vault12/glow.ts">
    <img src="https://travis-ci.com/vault12/glow.ts.svg?branch=master" alt="Travis Build Status" />
  </a>
  <a href="http://makeapullrequest.com">
    <img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg" alt="PRs welcome" />
  </a>
  <a href="https://opensource.org/licenses/MIT">
    <img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="MIT License" />
  </a>
</p>

<p align="center">
  <a href="https://david-dm.org/vault12/glow.ts#info=dependencies">
    <img src="https://david-dm.org/vault12/glow.ts.svg" alt="dependency Status" />
  </a>
  <a href="https://david-dm.org/vault12/glow.ts#info=devDependencies">
    <img src="https://david-dm.org/vault12/glow.ts/dev-status.svg" alt="devDependency Status" />
  </a>
  <a href="https://twitter.com/_Vault12_">
    <img src="https://img.shields.io/twitter/follow/_Vault12_?label=Follow&style=social" alt="Follow" />
  </a>
</p>

Glow is a client library for interacting with [Zax Cryptographic Relay](https://github.com/vault12/zax), a [NaCl-based Cryptographic Relay](https://s3-us-west-1.amazonaws.com/vault12/zax_infogfx.jpg).

## Running tests

Unit tests are powered by [Jest](https://jestjs.io). The engine runs all the tests in each `describe` section serially in the order they are described in the `.spec.ts` file.
By default, unit tests connect to a remote [Zax](https://github.com/vault12/zax) Cryptographic Relay Server on `https://z.vault12.com`.
You may also run tests on a local or any other test server by modifying the code in [src/tests.helper.ts#L1](src/tests.helper.ts#L1).

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
# Changelog

## [2.0.0](https://github.com/DevHatRo/outbound-smtp/compare/v1.1.0...v2.0.0) (2026-11-25)


### ⚠ BREAKING CHANGES

* **relay:** rate limits (RATE_LIMIT_*_PER_HOUR and --rate) count recipients, not messages. Smarthosts require a certificate valid for SMARTHOST_HOST and never fall back to plaintext, with or without credentials.

### Bug Fixes

* **relay:** close audit findings in queue, limits, smarthost TLS and DKIM ([#7](https://github.com/DevHatRo/outbound-smtp/issues/7)) ([03f3d14](https://github.com/DevHatRo/outbound-smtp/commit/03f3d14416ab19b84206453d5d2127c112752d5e))

## [1.1.0](https://github.com/DevHatRo/outbound-smtp/compare/v1.0.1...v1.1.0) (2026-11-25)


### Features

* add LOG_RECIPIENTS to log full recipient addresses ([#5](https://github.com/DevHatRo/outbound-smtp/issues/5)) ([12b09de](https://github.com/DevHatRo/outbound-smtp/commit/12b09dedc4faa28d056893d377b3d6ab41b1963c))

## [1.0.1](https://github.com/DevHatRo/outbound-smtp/compare/v1.0.0...v1.0.1) (2026-11-25)


### Bug Fixes

* address review findings from the initial implementation ([#3](https://github.com/DevHatRo/outbound-smtp/issues/3)) ([1aa538a](https://github.com/DevHatRo/outbound-smtp/commit/1aa538a07ceb9e6c6490b76153b37bf1a89c6206))

## 1.0.0 (2026-11-25)


### Features

* outbound-only SMTP relay with DKIM signing ([08c278f](https://github.com/DevHatRo/outbound-smtp/commit/08c278f4c97c16c96a6237f52b827671e477b3d3))

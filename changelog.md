# Change Log
This file contains all the notable changes done to the Ballerina Crypto package through the releases.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- [Address CVE-2023-33201 Bouncy Castle vulnerability](https://github.com/ballerina-platform/ballerina-standard-library/issues/4776)

## [2.4.0] - 2023-06-30

- This version maintains the latest dependency versions.

## [2.3.1] - 2023-06-01

- This version maintains the latest dependency versions.

## [2.3.0] - 2022-11-29

### Changed
- [API docs updated](https://github.com/ballerina-platform/ballerina-standard-library/issues/3463)

## [2.0.0] - 2021-10-10

### Added
- [Improve hash APIs for cryptographic salt](https://github.com/ballerina-platform/ballerina-standard-library/issues/1517)

### Fixed
- [Fails to decode unencrypted RSA private key from PEM encoded key pair](https://github.com/ballerina-platform/ballerina-standard-library/issues/1658)

## [1.1.0-alpha6] - 2021-04-02

### Changed
- Remove usages of `checkpanic` for type narrowing

## [1.1.0-alpha5] - 2021-03-19

### Added
- [Improve private key decoding for PKCS8 format](https://github.com/ballerina-platform/ballerina-standard-library/issues/1208)

### Changed
- Update error types
- Update for Time API changes

## [1.1.0-alpha4] - 2021-02-20

### Changed
- [Add support to decode private/public keys from key/cert files](https://github.com/ballerina-platform/ballerina-standard-library/issues/67)
- [Update crypto HMAC APIs and refactor code](https://github.com/ballerina-platform/ballerina-standard-library/issues/908)

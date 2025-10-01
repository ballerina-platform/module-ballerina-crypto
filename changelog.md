# Change Log
This file contains all the notable changes done to the Ballerina Crypto package through the releases.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.9.1] - 2025-09-30

### Fixed
- [Implement optional close method check for BStream](https://github.com/ballerina-platform/ballerina-library/issues/8288)

## [2.9.0] - 2025-03-12

### Changed
- [Update OIDS of NIST approved post quantum algorithms](https://github.com/ballerina-platform/ballerina-library/issues/7678)

## [2.8.0] - 2025-02-11

### Added
- [Introduce new APIs to support PGP encryption and decryption with streams](https://github.com/ballerina-platform/ballerina-library/issues/7064)
- [Introduce new APIs to support Bcrypt and Argon2 hashing and verification](https://github.com/ballerina-platform/ballerina-library/issues/2744)
- [Introduce Keccak-256 hashing algorithm](https://github.com/ballerina-platform/ballerina-library/issues/7509)

## [2.7.2] - 2024-05-30

### Added
- [Implement the support for reading private/public keys from the content](https://github.com/ballerina-platform/ballerina-library/issues/6513)

## [2.7.1] - 2024-05-14

### Added
- [Introduce new APIs to support ML-DSA (Dilithium) and ML-KEM (Kyber) post-quantum crypto algorithms](https://github.com/ballerina-platform/ballerina-library/issues/6201)

## [2.6.2] - 2023-12-19

### Added
- [Introduce new APIs to sign and verify using SHA256withECDSA](https://github.com/ballerina-platform/ballerina-library/issues/5889)

## [2.6.1] - 2023-12-12

### Added
- [Introduce new APIs to decode private and public keys from files](https://github.com/ballerina-platform/ballerina-library/issues/5871)

## [2.6.0] - 2023-12-08

### Added
- [Introduce new APIs to interact with EC private keys and public keys](https://github.com/ballerina-platform/ballerina-library/issues/5821)

## [2.5.0] - 2023-09-15

### Changed
- [Remove support for AES/GCM/PKCS5ZPadding algorithm](https://github.com/ballerina-platform/ballerina-standard-library/issues/4775)

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

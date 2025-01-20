# Proposal: Introduce Password Hashing Support to Ballerina Crypto Module

_Authors_: @randilt
_Reviewers_:
_Created_: 2024/01/20
_Updated_: 2024/01/20
_Issue_: [#2744](https://github.com/ballerina-platform/ballerina-library/issues/2744)

## Summary

Currently, the Ballerina crypto module lacks built-in support for secure password hashing. This proposal introduces two industry-standard password hashing algorithms - BCrypt and Argon2id - to provide developers with secure options for password hashing and verification.

## Goals

- Introduce BCrypt password hashing and verification support
- Introduce Argon2id password hashing and verification support
- Provide configurable parameters for both algorithms to allow fine-tuning of security levels

## Motivation

Password hashing is a critical security requirement for any application that handles user authentication. While the crypto module provides various cryptographic operations, it currently lacks dedicated password hashing functionality. BCrypt and Argon2id were chosen because:

1. [BCrypt](https://en.wikipedia.org/wiki/Bcrypt) is a well-established algorithm with a proven track record, adaptive work factor, and built-in salt generation
2. Argon2id is the winner of the [Password Hashing Competition](https://www.password-hashing.net/), providing strong defense against both GPU-based and side-channel attacks through configurable memory, parallelism, and iteration parameters

## Description

The purpose of this proposal is to introduce secure password hashing capabilities to the Ballerina crypto module.

### API additions

#### BCrypt Functions

A new API will be added to generate BCrypt hashes with configurable work factor:

```ballerina
public isolated function hashBcrypt(string password, int workFactor = 12) returns string|Error;
```

A corresponding verification API:

```ballerina
public isolated function verifyBcrypt(string password, string hashedPassword) returns boolean|Error;
```

#### Argon2id Functions

A new API will be added for Argon2id hashing with configurable parameters:

```ballerina
public isolated function hashArgon2(
    string password,
    int iterations = 3,
    int memory = 65536,
    int parallelism = 4
) returns string|Error;
```

A corresponding verification API:

```ballerina
public isolated function verifyArgon2(string password, string hashedPassword) returns boolean|Error;
```

### Proposed Future Additions

The following features are planned for future iterations:

#### Salt Management
- Add support for custom salt generation with configurable length
- Extend hashing APIs to accept custom salts
- Expose utility functions used for salt generation in native implementation to Ballerina side.

#### Additional Algorithms
- Expand Argon2 family support:
  - Argon2i for side-channel attack resistance
  - Argon2d for maximum GPU cracking resistance
- Add support for other popular password hashing algorithms:
  - PBKDF2 with configurable hash functions
  - scrypt with configurable parameters
  - yescrypt

#### API Enhancements
- Add functions to upgrade hashes when security parameters need adjustment
- Add support for pepper in password hashing

These additions will be proposed and implemented in separate iterations to maintain modularity and allow proper review and testing of each feature.
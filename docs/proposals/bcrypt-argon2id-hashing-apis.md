# Proposal: Introduce Password Hashing Support to Ballerina Crypto Module

*Authors*: @randilt
*Reviewers*: 
*Created*: 2024/01/20
*Updated*: 2024/01/20
*Issue*: [#2744](https://github.com/ballerina-platform/ballerina-library/issues/2744)

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

### Default Parameters

- BCrypt:
  - work factor = 12 (2^12 iterations)
- Argon2id:
  - iterations = 3 (time cost)
  - memory = 65536 KB (64MB)
  - parallelism = 4 threads

### Implementation Details

- Both algorithms will automatically generate and handle cryptographic salts
- The hashed outputs will be returned in their respective standard formats:
  - BCrypt: `$2a$12$LQV3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewYpwBAM7RHF.H9m`
  - Argon2id: `$argon2id$v=19$m=65536,t=3,p=4$[salt]$[hash]`
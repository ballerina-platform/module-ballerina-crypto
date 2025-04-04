# Proposal: Introduce PBKDF2-Based Password Hashing to Ballerina Crypto Module

_Authors_: @randilt  
_Reviewers_:  
_Created_: 2025/03/18  
_Updated_: 2025/03/18  
_Issues_: [#43926](https://github.com/ballerina-platform/ballerina-lang/issues/43926)

## Summary

The Ballerina crypto module currently lacks built-in support for PBKDF2 password hashing, a widely used key derivation function for secure password storage. This proposal introduces two new APIs to provide PBKDF2-based password hashing and verification.

## Goals

- Introduce PBKDF2 password hashing support with configurable parameters
- Provide a verification function to check hashed passwords against user inputs
- Support common HMAC algorithms (`SHA1`, `SHA256`, `SHA512`) and iteration count customization

## Motivation

Password hashing is a fundamental security requirement for authentication systems. PBKDF2 is a widely recognized key derivation function that enhances security by applying multiple iterations of a cryptographic hash function. By integrating PBKDF2 support, the Ballerina crypto module will offer a standardized and secure method for password storage and verification.

## Description

This proposal aims to introduce secure PBKDF2 password hashing and verification capabilities in the Ballerina crypto module.

### API Additions

#### PBKDF2 Hashing Function

A new API will be introduced to generate PBKDF2 hashes with configurable parameters:

```ballerina
public enum HmacAlgorithm {
    SHA1,
    SHA256,
    SHA512
}

public isolated function hashPbkdf2(
    string password,
    int iterations = 10000,
    HmacAlgorithm algorithm = SHA256
) returns string|Error;
```

#### PBKDF2 Verification Function

A corresponding API will be introduced to verify a password against a PBKDF2 hash:

```ballerina
public isolated function verifyPbkdf2(
    string password,
    string hashedPassword
) returns boolean|Error;
```

These functions will allow developers to securely hash and verify passwords using PBKDF2 with customizable parameters for increased security.

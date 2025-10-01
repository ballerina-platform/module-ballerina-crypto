# Proposal: Introduce RSASSA-PSS (PS256) Signature Support to Ballerina Crypto Module

_Authors_: @randilt  
_Reviewers_:  
_Created_: 2025/10/01  
_Updated_: 2025/10/01  
_Issue_: [#8292](https://github.com/ballerina-platform/ballerina-library/issues/8292)

## Summary

This proposal introduces support for the RSASSA-PSS signature scheme with SHA-256 (PS256) to the Ballerina Crypto Module. Currently, only classic RSA signatures (PKCS#1 v1.5) are available, but RSASSA-PSS provides enhanced security properties and is increasingly required by modern cryptographic standards and protocols.

## Goals

- Provide support for RSASSA-PSS signature generation with SHA-256
- Provide support for RSASSA-PSS signature verification with SHA-256
- Enable higher-level modules like JWT to utilize PS256 signatures

## Motivation

The Ballerina Crypto Module currently supports several RSA signature algorithms using PKCS#1 v1.5 padding (RSA-MD5, RSA-SHA1, RSA-SHA256, RSA-SHA384, RSA-SHA512). However, RSASSA-PSS, which is defined in RFC 8017 and provides enhanced security properties, is not yet supported.

RSASSA-PSS offers several advantages over PKCS#1 v1.5:

1. **Provable Security**: RSASSA-PSS has a security proof in the random oracle model
2. **Probabilistic Signatures**: Uses random salt generation, making signatures non-deterministic
3. **Modern Standard**: Required by many modern protocols and standards, including JWT RS256 alternative (PS256)
4. **Recommended by Standards**: NIST and other standards bodies recommend RSASSA-PSS over PKCS#1 v1.5

The lack of native support for RSASSA-PSS limits the cryptographic capabilities of Ballerina applications, particularly those implementing modern security protocols that require or prefer PS256 signatures.

## Description

This proposal adds RSASSA-PSS signature generation and verification with SHA-256 to the Ballerina Crypto Module, following the same architectural patterns as existing RSA signature functions.

The key functionalities expected from this change are:

- API to generate RSASSA-PSS signatures with `crypto:signRsaSsaPss256`
- API to verify RSASSA-PSS signatures with `crypto:verifyRsaSsaPss256Signature`

### API additions

Two new APIs will be added following the existing RSA signature function patterns:

```ballerina
# Returns the RSASSA-PSS based signature value for the given data.
#
# + input - The content to be signed
# + privateKey - Private key used for signing
# + return - The generated signature or else a `crypto:Error` if the private key is invalid
public isolated function signRsaSsaPss256(byte[] input, PrivateKey privateKey) returns byte[]|Error;
```

```ballerina
# Verifies the RSASSA-PSS based signature.
#
# + data - The content to be verified
# + signature - Signature value
# + publicKey - Public key used for verification
# + return - Validity of the signature or else a `crypto:Error` if the key is invalid
public isolated function verifyRsaSsaPss256Signature(byte[] data, byte[] signature, PublicKey publicKey) returns boolean|Error;
```

### Implementation Details

The implementation follows the existing architecture:

1. **Java Native Implementation**: Uses Java's `Signature.getInstance("SHA256withRSAandMGF1")` with default PSS parameters
2. **Algorithm String**: Uses `"SHA256withRSAandMGF1"` directly as string literal, consistent with other algorithms
3. **Method Naming**: Follows the pattern `signRsaSsaPss256` and `verifyRsaSsaPss256Signature`
4. **Documentation**: Matches the style and format of existing signature functions

### PSS Parameters

The implementation uses Java's default RSASSA-PSS parameters:

- **Hash Algorithm**: SHA-256
- **MGF**: MGF1 with SHA-256
- **Salt Length**: Same as hash length (32 bytes for SHA-256)
- **Trailer Field**: 1 (standard value)

These parameters align with common RSASSA-PSS usage and provide strong security guarantees.

## Testing

The implementation includes comprehensive test coverage following the existing test patterns:

1. **Basic Signing Test**: Verifies signature generation returns valid length (probabilistic nature prevents deterministic comparison)
2. **Invalid Key Test**: Verifies proper error handling with invalid private keys
3. **Sign-Verify Test**: Tests complete workflow of signing with private key and verifying with corresponding public key

## Backward Compatibility

This addition is fully backward compatible as it only adds new functions without modifying existing APIs or behavior.

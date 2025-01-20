# Proposal: Introduce support for keccak-256 hashing in the Ballerina Crypto Module

_Authors_: @thil4n  
_Reviewers_:   
_Created_: 2024/05/29  
_Updated_: 2022/05/29  
_Issue_: [#7509](https://github.com/ballerina-platform/ballerina-library/issues/7509)  

## Summary

This proposal introduces support for the keccak-256 hashing algorithm in the Ballerina Crypto Module. The keccak-256 algorithm is a cryptographic hash function and a critical component of many blockchain systems, including Ethereum. Adding keccak-256 will expand the cryptographic capabilities of the Ballerina Crypto Module.

## Goals

- Provide support for the keccak-256 hashing algorithm in the Ballerina Crypto Module.

## Motivation

The Ballerina Crypto Module currently supports several hashing algorithms, such as SHA-256, SHA-512, and others. However, keccak-256, a widely-used cryptographic hash function, is not yet supported. This function is essential for blockchain applications, as it is the primary hashing algorithm in Ethereum.

The lack of native support for keccak-256 requires developers to rely on external libraries or workarounds, which adds complexity and reduces the seamless integration of blockchain-related functionality in Ballerina. Adding native support for keccak-256 will address this gap and enhance Ballerina's suitability for blockchain-related projects.

## Description

This proposal adds keccak-256 hashing to the Ballerina Crypto Module.

The key functionalities expected from this change are as follows,

- API to retrieve the hash of the input with `crypto:hashKeccak256`.

### API additions

A new API will be added to retrieve the hash of the input with `crypto:hashKeccak256`

```ballerina
public isolated function hashKeccak256(byte[] input, byte[]? salt = ()) returns byte[];
```

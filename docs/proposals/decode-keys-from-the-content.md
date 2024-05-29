# Proposal: Introduce support to retrieve `crypto:PrivateKey` and `crypto:PublicKey` by directly using the content

_Authors_: @ayeshLK  
_Reviewers_: @shafreenAnfar @bhashinee @NipunaRanasinghe  
_Created_: 2024/05/29  
_Updated_: 2022/05/29  
_Issue_: [#6517](https://github.com/ballerina-platform/ballerina-standard-library/issues/6517)  

## Summary

Cryptographic private keys and certificates are represented as `crypto:PrivateKey` or `crypto:PublicKey` in Ballerina.
Hence, it should be possible to retrieve a `crypto:PrivateKey` or a `crypto:PublicKey` by just using the content of the
private key or the certificate.

## Goals

- Introduce support to retrieve `crypto:PrivateKey` or `crypto:PublicKey` by directly using the content

## Motivation

In Ballerina, cryptographic private keys and certificates are represented as `crypto:PrivateKey` and `crypto:PublicKey`,
respectively. Currently, a developer must provide the file path to retrieve either a `crypto:PrivateKey` or a
`crypto:PublicKey`. However, for greater flexibility, developers should also have the option to retrieve these
keys using the raw content of the file.

## Description

As mentioned in the Goals section the purpose of this proposal is to introduce support to retrieve
`crypto:PrivateKey` or `crypto:PublicKey` by directly using the content.

The key functionalities expected from this change are as follows,

- API to retrieve `crypto:PrivateKey` using the content of the private key.
- API to retrieve `crypto:PublicKey` using the content of the certificate

### API additions

A new API will be added to retrieve `crypto:PrivateKey` using the content of the private key.

```ballerina
public isolated function decodeRsaPrivateKeyFromContent(byte[] content, string? keyPassword = ()) returns crypto:PrivateKey|crypto:Error;
```

A new API will be added to retrieve `crypto:PublicKey` using the content of the certificate.

```ballerina
public isolated function decodeRsaPublicKeyFromContent(byte[] content) returns crypto:PublicKey|crypto:Error;
```

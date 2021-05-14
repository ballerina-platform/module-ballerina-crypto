## Overview

This module provides the common cryptographic mechanisms with different algorithms.

The Ballerina Crypto module facilitates APIs to do operations like hashing, HMAC generation, checksum generation, encryption, decryption, digitally signing data and verifying digitally signed data, etc. with different cryptographic algorithms.

### Hashes

Crypto module supports generating hashes with 5 different hash algorithms MD5, SHA1, SHA256, SHA384, and SHA512. Also, it supports generating the CRC32B checksum.

### HMAC

Crypto module supports generating HMAC with 5 different hash algorithms MD5, SHA1, SHA256, SHA384, and SHA512.

### Decode Private/Public Key

Crypto module supports decoding RSA private key from a `.p12` file and a key file in `PEM` format. Also, supports decoding a public key from a `.p12` file and a certificate file in `X509` format. Additionally, this supports building an RSA public key with the modulus and the exponent parameters.

### Encrypt and Decrypt

Crypto module supports both symmetric key encryption/decryption and asymmetric key encryption/decryption. RSA algorithm can be used for symmetric key encryption/decryption with the use of private and public keys. AES algorithm can be used for asymmetric key encryption/decryption with the use of a shared key.

### Sign and Verify

Crypto module supports for signing data using the RSA private key and verification of signature using the RSA public key. This supports MD5, SHA1, SHA256, SHA384, and SHA512 digesting algorithms as well.

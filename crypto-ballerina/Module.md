## Overview

This module provides the common cryptographic mechanisms with different algorithms.

The Ballerina Crypto module facilitates APIs to do operations like hashing, HMAC generation, checksum generation, encryption, decryption, signing data digitally, verifying digitally signed data, etc., with different cryptographic algorithms.

### Hashes

The `crypto` module supports generating hashes with 5 different hash algorithms MD5, SHA1, SHA256, SHA384, and SHA512. Also, it supports generating the CRC32B checksum.

### HMAC

The `crypto` module supports generating HMAC with 5 different hash algorithms: MD5, SHA1, SHA256, SHA384, and SHA512.

### Decode Private/Public Key

The `crypto` module supports decoding the RSA private key from a `.p12` file and a key file in the `PEM` format. Also, it supports decoding a public key from a `.p12` file and a certificate file in the `X509` format. Additionally, this supports building an RSA public key with the modulus and exponent parameters.

### Encrypt and Decrypt

The `crypto` module supports both symmetric key encryption/decryption and asymmetric key encryption/decryption. The RSA algorithm can be used for symmetric-key encryption/decryption with the use of private and public keys. The AES algorithm can be used for asymmetric-key encryption/decryption with the use of a shared key.

### Sign and Verify

The `crypto` module supports signing data using the RSA private key and verification of the signature using the RSA public key. This supports MD5, SHA1, SHA256, SHA384, and SHA512 digesting algorithms as well.

## Overview

This module provides the common cryptographic mechanisms with different algorithms.

The Ballerina Crypto module facilitates APIs to do operations like hashing, HMAC generation, checksum generation, encryption, decryption, digitally signing data and verifying digitally signed data etc. with different cryptographic algorithms.

### Hashes

Crypto module supports to generate hashes with 5 different hash algorithms MD5, SHA1, SHA256, SHA384 and SHA512. Also, it supports to generate the CRC32B checksum.

### HMAC

Crypto module supports to generate HMAC with 5 different hash algorithms MD5, SHA1, SHA256, SHA384 and SHA512.

### Decode Private/Public Key

Crypto module supports to decode RSA private key from a `.p12` file and a key file in `PEM` format. Also, supports to decode a public key from a `.p12` file and a certificate file in `X509` format. Additionally, this supports to build an RSA public key with the modulus and the exponent parameters.

### Encrypt and Decrypt

Crypto module supports to both symmetric key encryption/decryption and asymmetric key encryption/decryption. RSA algorithm can be used for symmetric key encryption/decryption with the use of the private and public keys. AES algorithm can be used for asymmetric key encryption/decryption with the use of shared key.

### Sign and Verify

Crypto module supports for signing data using the RSA private key and verification of signature using the RSA public key. This supports MD5, SHA1, SHA256, SHA384 and SHA512 digesting algorithms as well.

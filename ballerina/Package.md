## Package Overview

This package provides common cryptographic mechanisms based on different algorithms.

The Ballerina `crypto` package facilitates APIs to do operations like hashing, HMAC generation, checksum generation, encryption, decryption, signing data digitally, verifying digitally signed data, etc., with different cryptographic algorithms.

### Hashes

The `crypto` package supports generating hashes with 5 different hash algorithms MD5, SHA1, SHA256, SHA384, and SHA512. Also, it supports generating the CRC32B checksum.

### HMAC

The `crypto` package supports generating HMAC with 5 different hash algorithms: MD5, SHA1, SHA256, SHA384, and SHA512.

### Decode Private/Public Key

The `crypto` package supports decoding the RSA private key from a `.p12` file and a key file in the `PEM` format. Also, it supports decoding a public key from a `.p12` file and a certificate file in the `X509` format. Additionally, this supports building an RSA public key with the modulus and exponent parameters.

### Encrypt and Decrypt

The `crypto` package supports both symmetric key encryption/decryption and asymmetric key encryption/decryption. The RSA algorithm can be used for symmetric-key encryption/decryption with the use of private and public keys. The AES algorithm can be used for asymmetric-key encryption/decryption with the use of a shared key.

### Sign and Verify

The `crypto` package supports signing data using the RSA private key and verification of the signature using the RSA public key. This supports MD5, SHA1, SHA256, SHA384, and SHA512 digesting algorithms as well.

## Report Issues

To report bugs, request new features, start new discussions, view project boards, etc., go to the [Ballerina standard library parent repository](https://github.com/ballerina-platform/ballerina-standard-library).

## Useful Links

- Chat live with us via our [Slack channel](https://ballerina.io/community/slack/).
- Post all technical questions on Stack Overflow with the [#ballerina](https://stackoverflow.com/questions/tagged/ballerina) tag.

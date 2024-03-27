## Package overview

This package provides common cryptographic mechanisms based on different algorithms.

The Ballerina `crypto` package facilitates APIs to do operations like hashing, HMAC generation, checksum generation, encryption, decryption, signing data digitally, verifying digitally signed data, etc., with different cryptographic algorithms.

### Hashes

The `crypto` package supports generating hashes with 5 different hash algorithms MD5, SHA1, SHA256, SHA384, and SHA512. Also, it supports generating the CRC32B checksum.

### HMAC

The `crypto` package supports generating HMAC with 5 different hash algorithms: MD5, SHA1, SHA256, SHA384, and SHA512.

### Decode private/public key

The `crypto` package supports decoding the RSA private key from a `.p12` file and a key file in the `PEM` format. Also, it supports decoding a public key from a `.p12` file and a certificate file in the `X509` format. Additionally, this supports building an RSA public key with the modulus and exponent parameters.

### Encrypt and decrypt

The `crypto` package supports both symmetric key encryption/decryption and asymmetric key encryption/decryption. The RSA algorithm can be used for asymmetric-key encryption/decryption with the use of private and public keys. The AES algorithm can be used for symmetric-key encryption/decryption with the use of a shared key.

### Sign and verify

The `crypto` package supports signing data using the RSA private key and verification of the signature using the RSA public key. This supports MD5, SHA1, SHA256, SHA384, and SHA512 digesting algorithms, and ML-DSA-65 post-quantum signature algorithm as well.

### Key Derivation Functions (KDF)

The `crypto` package supports HMAC-based Key Derivation Function (HKDF). HKDF is a key derivation function that uses a Hash-based Message Authentication Code (HMAC) to derive keys.

### Key Exchange Mechanisms (KEM)

The `crypto` package supports Key Exchange Mechanisms (KEM). It includes RSA-KEM and post-quantum ML-KEM-768 for both encapsulation and decapsulation.

### Hybrid Public Key Encryption (HPKE)

The `crypto` package supports Hybrid Public Key Encryption (HPKE). It supportspost-quantum ML-KEM-768-HPKE and RSA-KEM-ML-KEM-768-HPKE for encryption and decryption.

## Report issues

To report bugs, request new features, start new discussions, view project boards, etc., go to the [Ballerina standard library parent repository](https://github.com/ballerina-platform/ballerina-standard-library).

## Useful links

- Chat live with us via our [Discord server](https://discord.gg/ballerinalang).
- Post all technical questions on Stack Overflow with the [#ballerina](https://stackoverflow.com/questions/tagged/ballerina) tag.

/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package io.ballerina.stdlib.crypto;

import io.ballerina.runtime.api.utils.StringUtils;
import io.ballerina.runtime.api.values.BString;

/**
 * Constants related to Ballerina crypto stdlib.
 *
 * @since 0.990.3
 */
public class Constants {

    private Constants() {}

    // Record used to reference to a private key.
    public static final String PRIVATE_KEY_RECORD = "PrivateKey";

    // Record used to reference to a public key.
    public static final String PUBLIC_KEY_RECORD = "PublicKey";

    // Record used to reference to a public key certificate.
    public static final String CERTIFICATE_RECORD = "Certificate";

    // Record used to reference to an encapsulated key.
    public static final String ENCAPSULATED_RESULT_RECORD = "EncapsulationResult";

    // Native data key for private key within the PrivateKey record.
    public static final String NATIVE_DATA_PRIVATE_KEY = "NATIVE_DATA_PRIVATE_KEY";

    public static final String NATIVE_DATA_EC_PRIVATE_KEY = "NATIVE_DATA_EC_PRIVATE_KEY";

    // Native data key for private key within the PublicKey record.
    public static final String NATIVE_DATA_PUBLIC_KEY = "NATIVE_DATA_PUBLIC_KEY";

    // Native data key for private key within the PublicKey record.
    public static final String NATIVE_DATA_PUBLIC_KEY_CERTIFICATE = "NATIVE_DATA_PUBLIC_KEY_CERTIFICATE";

    // Fields of `KeyStore` record.
    public static final BString KEY_STORE_RECORD_PATH_FIELD = StringUtils.fromString("path");
    public static final BString KEY_STORE_RECORD_PASSWORD_FIELD = StringUtils.fromString("password");

    // Fields of `PrivateKey` record.
    public static final String PRIVATE_KEY_RECORD_ALGORITHM_FIELD = "algorithm";

    // Fields of `PublicKey` record.
    public static final String PUBLIC_KEY_RECORD_ALGORITHM_FIELD = "algorithm";
    public static final String PUBLIC_KEY_RECORD_CERTIFICATE_FIELD = "certificate";

    // Fields of `Certificate` record.
    public static final String CERTIFICATE_RECORD_VERSION_FIELD = "version0";
    public static final String CERTIFICATE_RECORD_SERIAL_FIELD = "serial";
    public static final String CERTIFICATE_RECORD_ISSUER_FIELD = "issuer";
    public static final String CERTIFICATE_RECORD_SUBJECT_FIELD = "subject";
    public static final String CERTIFICATE_RECORD_NOT_BEFORE_FIELD = "notBefore";
    public static final String CERTIFICATE_RECORD_NOT_AFTER_FIELD = "notAfter";
    public static final String CERTIFICATE_RECORD_SIGNATURE_FIELD = "signature";
    public static final String CERTIFICATE_RECORD_SIGNATURE_ALG_FIELD = "signingAlgorithm";

    // Fields of `EncapsulationResult` record.
    public static final String ENCAPSULATED_RESULT_RECORD_ENCAPSULATED_FIELD = "encapsulatedSecret";
    public static final String ENCAPSULATED_RESULT_RECORD_SECRET_FIELD = "sharedSecret";

    // Fields of `KeyStoreConfig` record.
    public static final BString KEY_STORE_CONFIG_RECORD_KEY_STORE_FIELD = StringUtils.fromString("keyStore");
    public static final BString KEY_STORE_CONFIG_RECORD_KEY_ALIAS_FIELD = StringUtils.fromString("keyAlias");
    public static final BString KEY_STORE_CONFIG_RECORD_KEY_PASSWORD_FIELD = StringUtils.fromString("keyPassword");

    // Fields of `TrustStoreConfig` record.
    public static final BString TRUST_STORE_CONFIG_RECORD_TRUST_STORE_FIELD = StringUtils.fromString("trustStore");
    public static final BString TRUST_STORE_CONFIG_RECORD_CERT_ALIAS_FIELD = StringUtils.fromString("certAlias");

    // Fields of `PrivateKeyConfig` record.
    public static final BString PRIVATE_KEY_CONFIG_RECORD_KEY_FILE_FIELD = StringUtils.fromString("keyFile");
    public static final BString PRIVATE_KEY_CONFIG_RECORD_KEY_PASSWORD_FIELD = StringUtils.fromString("keyPassword");

    // Fields of `PublicKeyConfig` record.
    public static final BString PUBLIC_KEY_CONFIG_RECORD_CERT_FILE_FIELD = StringUtils.fromString("certFile");

    // Crypto error type ID
    static final String CRYPTO_ERROR = "Error";

    // PKCS12 KeyStore type
    public static final String KEYSTORE_TYPE_PKCS12 = "PKCS12";

    // X509 certificate type
    public static final String CERTIFICATE_TYPE_X509 = "X.509";

    // RSA key algorithm
    public static final String RSA_ALGORITHM = "RSA";

    // ML-DSA-65 signing algorithm
    public static final String MLDSA65_ALGORITHM = "ML-DSA-65";

    // ML-KEM-768 key encapsulation mechanism
    public static final String MLKEM768_ALGORITHM = "ML-KEM-768";

    // EC key algorithm
    public static final String EC_ALGORITHM = "EC";

    // GMT timezone name used for X509 validity times
    public static final String TIMEZONE_GMT = "GMT";

    // Encryption modes
    public static final String CBC = "CBC";
    public static final String ECB = "ECB";
    public static final String GCM = "GCM";
    public static final String AES = "AES";
    public static final String RSA = "RSA";

    public static final String COMPRESSED_DATA_STREAM = "COMPRESSED_DATA_STREAM";
    public static final String DATA_STREAM = "DATA_STREAM";
    public static final String TARGET_STREAM = "TARGET_STREAM";
    public static final String ENCRYPTED_OUTPUT_STREAM = "ENCRYPTED_OUTPUT_STREAM";
    public static final String INPUT_STREAM_TO_ENCRYPT = "INPUT_STREAM_TO_ENCRYPT";
    public static final String PIPED_INPUT_STREAM = "PIPED_INPUT_STREAM";
    public static final String PIPED_OUTPUT_STREAM = "PIPED_OUTPUT_STREAM";
    public static final String END_OF_INPUT_STREAM = "END_OF_INPUT_STREAM";
    public static final String COMPRESSED_DATA_GENERATOR = "COMPRESSED_DATA_GENERATOR";
    public static final String KEY_ENCRYPTED_DATA = "KEY_ENCRYPTED_DATA";

    // Hashing Algorithms
    public static final String MD5 = "MD5";
    public static final String SHA1 = "SHA-1";
    public static final String SHA256 = "SHA-256";
    public static final String SHA384 = "SHA-384";
    public static final String SHA512 = "SHA-512";
    public static final String KECCAK256 = "Keccak-256";

    // Password hashing constants
    public static final String BCRYPT_HASH_FORMAT = "$2a$%02d$%s";
    public static final String ARGON2_SALT_FORMAT = "$argon2id$v=19$m=%d,t=%d,p=%d$%s";
    public static final String ARGON2_HASH_FORMAT = "$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s";
    public static final String PBKDF2_HASH_PATTERN = 
                        "\\$pbkdf2-(\\w+)\\$i=(\\d+)\\$([A-Za-z0-9+/=]+)\\$([A-Za-z0-9+/=]+)";
    public static final String PBKDF2_SALT_FORMAT = "$pbkdf2-%s$i=%d$%s";
    public static final String PBKDF2_HASH_FORMAT = "$pbkdf2-%s$i=%d$%s$%s";
}

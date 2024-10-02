// Copyright (c) 2020 WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
//
// WSO2 Inc. licenses this file to you under the Apache License,
// Version 2.0 (the "License"); you may not use this file except
// in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

const KEYSTORE_PATH = "tests/resources/keyStore.p12";
const EC_KEYSTORE_PATH = "tests/resources/ec-keystore.pkcs12";
const MLDSA_KEYSTORE_PATH = "tests/resources/mldsa-keystore.pkcs12";
const MLKEM_KEYSTORE_PATH = "tests/resources/mlkem-keystore.pkcs12";
const ENCRYPTED_KEY_PAIR_PATH = "tests/resources/encryptedKeyPair.pem";
const KEY_PAIR_PATH = "tests/resources/keyPair.pem";
const ENCRYPTED_PRIVATE_KEY_PATH = "tests/resources/encryptedPrivate.key";
const PRIVATE_KEY_PATH = "tests/resources/private.key";
const X509_PUBLIC_CERT_PATH = "tests/resources/public.crt";
const EC_CERT_PATH = "tests/resources/ec-cert.crt";
const EC_PRIVATE_KEY_PATH = "tests/resources/ec-key.pem";
const MLDSA_CERT_PATH = "tests/resources/mldsa-cert.crt";
const MLDSA_PRIVATE_KEY_PATH = "tests/resources/mldsa-key.pem";
const MLKEM_CERT_PATH = "tests/resources/mlkem-cert.crt";
const MLKEM_PRIVATE_KEY_PATH = "tests/resources/mlkem-key.pem";

const INVALID_KEYSTORE_PATH = "tests/resources/cert/keyStore.p12.invalid";
const INVALID_PRIVATE_KEY_PATH = "tests/resources/cert/private.key.invalid";
const INVALID_PUBLIC_CERT_PATH = "tests/resources/cert/public.crt.invalid";

const PGP_PUBLIC_KEY_PATH = "tests/resources/public_key.asc";
const PGP_PRIVATE_KEY_PATH = "tests/resources/private_key.asc";
const PGP_INVALID_PRIVATE_KEY_PATH = "tests/resources/invalid_private_key.asc";
const PGP_PRIVATE_KEY_PASSPHRASE_PATH = "tests/resources/pgp_private_key_passphrase.txt";

const SAMPLE_TEXT = "tests/resources/sample.txt";
const TARGET_ENCRYPTION_OUTPUT = "target/encrypted_output.txt";
const TARGET_DECRYPTION_OUTPUT = "target/decrypted_output.txt";

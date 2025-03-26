/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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
package io.ballerina.stdlib.crypto.nativeimpl;

import io.ballerina.runtime.api.utils.StringUtils;
import io.ballerina.runtime.api.values.BString;
import io.ballerina.stdlib.crypto.CryptoUtils;
import io.ballerina.stdlib.crypto.PasswordUtils;
import org.bouncycastle.util.encoders.Base64;

import static io.ballerina.stdlib.crypto.Constants.ARGON2;
import static io.ballerina.stdlib.crypto.Constants.NOT_SUPPORTED_IN_FIPS_MODE;

/**
 * Native implementation of Argon2 password hashing functions.
 * Provides methods for hashing passwords, verifying hashes, and generating salts using the Argon2id algorithm.
 *
 * @since ...
 */
public class PasswordArgon2 {

    private PasswordArgon2() {}

    /**
     * Hash a password using Argon2 with default parameters.
     *
     * @param password the password to hash
     * @return hashed password string or error
     */
    public static Object hashPasswordArgon2(BString password) {
        return hashPasswordArgon2(password, PasswordUtils.DEFAULT_ITERATIONS, PasswordUtils.DEFAULT_MEMORY, 
        PasswordUtils.DEFAULT_PARALLELISM);
    }

    /**
     * Hash a password using Argon2 with custom parameters.
     *
     * @param password the password to hash
     * @param iterations number of iterations
     * @param memory memory usage in KB
     * @param parallelism number of parallel threads
     * @return hashed password string or error
     */
    public static Object hashPasswordArgon2(BString password, long iterations, long memory, long parallelism) {
        throw CryptoUtils.createFipsError(ARGON2 + NOT_SUPPORTED_IN_FIPS_MODE);
    }

    /**
     * Verify a password against an Argon2 hash.
     *
     * @param password the password to verify
     * @param hashedPassword the hashed password to verify against
     * @return true if password matches, false if not, or error if verification fails
     */
    public static Object verifyPasswordArgon2(BString password, BString hashedPassword) {
        return CryptoUtils.createFipsError(ARGON2 + NOT_SUPPORTED_IN_FIPS_MODE);
    }

    /**
     * Generate a salt string for Argon2 with default parameters.
     *
     * @return formatted salt string or error
     */
    public static Object generateSaltArgon2() {
        return generateSaltArgon2(PasswordUtils.DEFAULT_ITERATIONS, PasswordUtils.DEFAULT_MEMORY, 
        PasswordUtils.DEFAULT_PARALLELISM);
    }

    /**
     * Generate a salt string for Argon2 with custom parameters.
     *
     * @param iterations number of iterations
     * @param memory memory usage in KB
     * @param parallelism number of parallel threads
     * @return formatted salt string or error
     */
    public static Object generateSaltArgon2(long iterations, long memory, long parallelism) {
        try {
            byte[] salt = PasswordUtils.generateRandomSalt();
            String saltBase64 = Base64.toBase64String(salt);
            
            String result = PasswordUtils.formatArgon2Salt(memory, iterations, parallelism, saltBase64);
            
            return StringUtils.fromString(result);
        } catch (Exception e) {
            return CryptoUtils.createError("Error occurred while generating Argon2 salt: " + e.getMessage());
        }
    }
}

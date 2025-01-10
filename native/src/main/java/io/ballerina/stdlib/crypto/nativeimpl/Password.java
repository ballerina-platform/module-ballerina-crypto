/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package io.ballerina.stdlib.crypto.nativeimpl;

import io.ballerina.runtime.api.utils.StringUtils;
import io.ballerina.runtime.api.values.BString;
import io.ballerina.stdlib.crypto.CryptoUtils;
import io.ballerina.stdlib.crypto.PasswordUtils;
import org.bouncycastle.crypto.generators.BCrypt;

import java.nio.charset.StandardCharsets;

/**
 * Native implementation of BCrypt password hashing functions.
 * Provides methods for hashing passwords, verifying hashes, and generating salts using the BCrypt algorithm.
 *
 * @since ...
 */
public class Password {
    
    private Password() {}

    /**
     * Hash a password using BCrypt with a custom work factor.
     *
     * @param password the password to hash
     * @param workFactor the work factor to use (determines computational complexity)
     * @return hashed password string or error
     */
    public static Object hashPassword(BString password, long workFactor) {
        try {
            Object validationError = PasswordUtils.validateWorkFactor(workFactor);
            if (validationError != null) {
                return validationError;
            }

            byte[] salt = PasswordUtils.generateRandomSalt();
            byte[] passwordBytes = password.getValue().getBytes(StandardCharsets.UTF_8);
            byte[] hash = BCrypt.generate(passwordBytes, salt, (int) workFactor);
            
            return StringUtils.fromString(
                PasswordUtils.formatBCryptHash(workFactor, PasswordUtils.combine(salt, hash))
            );
        } catch (Exception e) {
            return CryptoUtils.createError("Error occurred while hashing password: " + e.getMessage());
        }
    }

    /**
     * Hash a password using BCrypt with the default work factor.
     *
     * @param password the password to hash
     * @return hashed password string or error
     */
    public static Object hashPassword(BString password) {
        return hashPassword(password, PasswordUtils.DEFAULT_WORK_FACTOR);
    }

    /**
     * Verify a password against a BCrypt hash.
     *
     * @param password the password to verify
     * @param hashedPassword the hashed password to verify against
     * @return true if password matches, false if not, or error if verification fails
     */
    public static Object verifyPassword(BString password, BString hashedPassword) {
        try {
            String hash = hashedPassword.getValue();
            if (!hash.startsWith("$2a$")) {
                return CryptoUtils.createError("Invalid hash format");
            }

            int workFactor = Integer.parseInt(hash.substring(4, 6));
            String saltAndHashBase64 = hash.substring(7);
            byte[] saltAndHash = org.bouncycastle.util.encoders.Base64.decode(saltAndHashBase64);

            byte[] salt = new byte[PasswordUtils.SALT_LENGTH];
            System.arraycopy(saltAndHash, 0, salt, 0, PasswordUtils.SALT_LENGTH);

            byte[] passwordBytes = password.getValue().getBytes(StandardCharsets.UTF_8);
            byte[] newHash = BCrypt.generate(passwordBytes, salt, workFactor);

            byte[] originalHash = new byte[saltAndHash.length - PasswordUtils.SALT_LENGTH];
            System.arraycopy(saltAndHash, PasswordUtils.SALT_LENGTH, originalHash, 0, originalHash.length);
            
            return PasswordUtils.constantTimeArrayEquals(newHash, originalHash);
        } catch (Exception e) {
            return CryptoUtils.createError("Error occurred while verifying password: " + e.getMessage());
        }
    }

    /**
     * Generate a salt string for BCrypt with a custom work factor.
     *
     * @param workFactor the work factor to use
     * @return formatted salt string or error
     */
    public static Object generateSalt(long workFactor) {
        try {
            Object validationError = PasswordUtils.validateWorkFactor(workFactor);
            if (validationError != null) {
                return validationError;
            }

            byte[] salt = PasswordUtils.generateRandomSalt();
            return StringUtils.fromString(
                PasswordUtils.formatBCryptHash(workFactor, salt)
            );
        } catch (Exception e) {
            return CryptoUtils.createError("Error occurred while generating salt: " + e.getMessage());
        }
    }

    /**
     * Generate a salt string for BCrypt with the default work factor.
     *
     * @return formatted salt string or error
     */
    public static Object generateSalt() {
        return generateSalt(PasswordUtils.DEFAULT_WORK_FACTOR);
    }
}

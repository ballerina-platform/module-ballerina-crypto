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
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.util.encoders.Base64;

import java.nio.charset.StandardCharsets;

/**
 * Native implementation of Argon2 password hashing functions.
 * Provides methods for hashing passwords, verifying hashes, and generating salts using the Argon2id algorithm.
 *
 * @since ...
 */
public class PasswordArgon2 {
    /**
     * Default number of iterations for Argon2.
     */
    private static final int DEFAULT_ITERATIONS = 3;
    
    /**
     * Default memory usage in KB (64MB).
     */
    private static final int DEFAULT_MEMORY = 65536;
    
    /**
     * Default number of parallel threads.
     */
    private static final int DEFAULT_PARALLELISM = 4;
    
    /**
     * Length of the generated hash in bytes.
     */
    private static final int HASH_LENGTH = 32;
    
    /**
     * Hash a password using Argon2 with default parameters.
     *
     * @param password the password to hash
     * @return hashed password string or error
     */
    public static Object hashPasswordArgon2(BString password) {
        return hashPasswordArgon2(password, DEFAULT_ITERATIONS, DEFAULT_MEMORY, DEFAULT_PARALLELISM);
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
        try {
            if (iterations <= 0) {
                return CryptoUtils.createError("Iterations must be positive");
            }
            if (memory < 8192) {
                return CryptoUtils.createError("Memory must be at least 8192 KB (8MB)");
            }
            if (parallelism <= 0) {
                return CryptoUtils.createError("Parallelism must be positive");
            }

            byte[] salt = PasswordUtils.generateRandomSalt();

            Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withSalt(salt)
                .withIterations((int) iterations)
                .withMemoryAsKB((int) memory)
                .withParallelism((int) parallelism)
                .build();

            byte[] hash = new byte[HASH_LENGTH];
            Argon2BytesGenerator generator = new Argon2BytesGenerator();
            generator.init(params);
            generator.generateBytes(password.getValue().getBytes(StandardCharsets.UTF_8), hash);

            String saltBase64 = Base64.toBase64String(salt);
            String hashBase64 = Base64.toBase64String(hash);
            
            String result = PasswordUtils.formatArgon2Hash(memory, iterations, parallelism, saltBase64, hashBase64);

            return StringUtils.fromString(result);
        } catch (Exception e) {
            return CryptoUtils.createError("Error occurred while hashing password with Argon2: " + e.getMessage());
        }
    }

    /**
     * Verify a password against an Argon2 hash.
     *
     * @param password the password to verify
     * @param hashedPassword the hashed password to verify against
     * @return true if password matches, false if not, or error if verification fails
     */
    public static Object verifyPasswordArgon2(BString password, BString hashedPassword) {
        try {
            String hash = hashedPassword.getValue();
            if (!hash.startsWith("$argon2id$")) {
                return CryptoUtils.createError("Invalid Argon2 hash format");
            }

            String[] parts = hash.split("\\$");
            if (parts.length != 6) {
                return CryptoUtils.createError("Invalid Argon2 hash format");
            }

            String[] params = parts[3].split(",");
            int memory = Integer.parseInt(params[0].substring(2));
            int iterations = Integer.parseInt(params[1].substring(2));
            int parallelism = Integer.parseInt(params[2].substring(2));

            byte[] salt = Base64.decode(parts[4]);
            byte[] originalHash = Base64.decode(parts[5]);

            Argon2Parameters parameters = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withSalt(salt)
                .withIterations(iterations)
                .withMemoryAsKB(memory)
                .withParallelism(parallelism)
                .build();

            byte[] newHash = new byte[HASH_LENGTH];
            Argon2BytesGenerator generator = new Argon2BytesGenerator();
            generator.init(parameters);
            generator.generateBytes(password.getValue().getBytes(StandardCharsets.UTF_8), newHash);

            return PasswordUtils.constantTimeArrayEquals(newHash, originalHash);
        } catch (Exception e) {
            return CryptoUtils.createError("Error occurred while verifying Argon2 password: " + e.getMessage());
        }
    }

    /**
     * Generate a salt string for Argon2 with default parameters.
     *
     * @return formatted salt string or error
     */
    public static Object generateSaltArgon2() {
        return generateSaltArgon2(DEFAULT_ITERATIONS, DEFAULT_MEMORY, DEFAULT_PARALLELISM);
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

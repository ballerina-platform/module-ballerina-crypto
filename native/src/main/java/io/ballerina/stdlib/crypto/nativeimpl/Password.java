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
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.generators.BCrypt;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.util.encoders.Base64;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Native implementation of password hashing functions.
 * Provides methods for hashing passwords, verifying hashes, and generating salts using
 * the BCrypt, Argon2id, and PBKDF2 algorithms.
 */
public class Password {
    
    private Password() {}

    // BCrypt methods
    
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
            if (password.getValue().length() == 0) {
                return CryptoUtils.createError("Password cannot be empty");
            } 

            byte[] salt = PasswordUtils.generateRandomSalt();
            byte[] passwordBytes = BCrypt.passwordToByteArray(password.getValue().toCharArray());
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

            byte[] passwordBytes = BCrypt.passwordToByteArray(password.getValue().toCharArray());
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

    // Argon2 methods

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
            if (password.getValue().length() == 0) {
                return CryptoUtils.createError("Password cannot be empty");
            } 

            byte[] salt = PasswordUtils.generateRandomSalt();

            Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withSalt(salt)
                .withIterations((int) iterations)
                .withMemoryAsKB((int) memory)
                .withParallelism((int) parallelism)
                .build();

            byte[] hash = new byte[PasswordUtils.HASH_LENGTH];
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

            byte[] newHash = new byte[PasswordUtils.HASH_LENGTH];
            Argon2BytesGenerator generator = new Argon2BytesGenerator();
            generator.init(parameters);
            generator.generateBytes(password.getValue().getBytes(StandardCharsets.UTF_8), newHash);

            return PasswordUtils.constantTimeArrayEquals(newHash, originalHash);
        } catch (Exception e) {
            return CryptoUtils.createError("Error occurred while verifying password: " + e.getMessage());
        }
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

    // PBKDF2 methods
    
    /**
     * Hash a password using PBKDF2 with default parameters.
     *
     * @param password the password to hash
     * @return hashed password string or error
     */
    public static Object hashPasswordPBKDF2(BString password) {
        return hashPasswordPBKDF2(password, PasswordUtils.DEFAULT_PBKDF2_ITERATIONS, 
                                  StringUtils.fromString(PasswordUtils.DEFAULT_PBKDF2_ALGORITHM));
    }
    
    /**
     * Hash a password using PBKDF2 with custom parameters.
     *
     * @param password the password to hash
     * @param iterations number of iterations
     * @param algorithm HMAC algorithm to use (SHA1, SHA256, SHA512)
     * @return hashed password string or error
     */
    public static Object hashPasswordPBKDF2(BString password, long iterations, BString algorithm) {
        try {
            String alg = algorithm.getValue();
            
            Object validationError = PasswordUtils.validatePBKDF2Iterations(iterations);
            if (validationError != null) {
                return validationError;
            }
            
            validationError = PasswordUtils.validatePBKDF2Algorithm(alg);
            if (validationError != null) {
                return validationError;
            }
            
            if (password.getValue().length() == 0) {
                return CryptoUtils.createError("Password cannot be empty");
            }
            
            byte[] salt = PasswordUtils.generateRandomSalt();
            
            byte[] hash = generatePBKDF2Hash(password.getValue(), salt, (int) iterations, alg);
            
            String saltBase64 = Base64.toBase64String(salt);
            String hashBase64 = Base64.toBase64String(hash);
            
            String result = PasswordUtils.formatPBKDF2Hash(alg, iterations, saltBase64, hashBase64);
            
            return StringUtils.fromString(result);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            return CryptoUtils.createError("Error occurred while hashing password with PBKDF2: " + e.getMessage());
        } catch (RuntimeException e) {
            return CryptoUtils.createError("Unexpected error: " + e.getMessage());
        } catch (Exception e) {
            return CryptoUtils.createError("Error occurred while hashing password with PBKDF2: " + e.getMessage());
        }
    }
    
    /**
     * Verify a password against a PBKDF2 hash.
     *
     * @param password the password to verify
     * @param hashedPassword the hashed password to verify against
     * @return true if password matches, false if not, or error if verification fails
     */
    public static Object verifyPasswordPBKDF2(BString password, BString hashedPassword) {
        try {
            String hash = hashedPassword.getValue();
            Pattern pattern = Pattern.compile("\\$pbkdf2-(\\w+)\\$i=(\\d+)\\$(\\w+)\\$(\\w+)");
            Matcher matcher = pattern.matcher(hash);
            
            if (!matcher.matches()) {
                return CryptoUtils.createError("Invalid PBKDF2 hash format");
            }
            
            String algorithm = matcher.group(1).toUpperCase(Locale.ROOT);
            int iterations = Integer.parseInt(matcher.group(2));
            byte[] salt = Base64.decode(matcher.group(3));
            byte[] originalHash = Base64.decode(matcher.group(4));
            
            byte[] newHash = generatePBKDF2Hash(password.getValue(), salt, iterations, algorithm);
            
            return PasswordUtils.constantTimeArrayEquals(newHash, originalHash);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            return CryptoUtils.createError("Error occurred while verifying password: " + e.getMessage());
        } catch (IllegalArgumentException e) {
            return CryptoUtils.createError("Invalid hash format: " + e.getMessage());
        } catch (RuntimeException e) {
            return CryptoUtils.createError("Unexpected error: " + e.getMessage());
        } catch (Exception e) {
            return CryptoUtils.createError("Error occurred while verifying password: " + e.getMessage());
        } 
    }
    
    /**
     * Generate a salt string for PBKDF2 with default parameters.
     *
     * @return formatted salt string or error
     */
    public static Object generateSaltPBKDF2() {
        return generateSaltPBKDF2(PasswordUtils.DEFAULT_PBKDF2_ITERATIONS, 
                                 StringUtils.fromString(PasswordUtils.DEFAULT_PBKDF2_ALGORITHM));
    }
    
    /**
     * Generate a salt string for PBKDF2 with custom parameters.
     *
     * @param iterations number of iterations
     * @param algorithm HMAC algorithm to use (SHA1, SHA256, SHA512)
     * @return formatted salt string or error
     */
    public static Object generateSaltPBKDF2(long iterations, BString algorithm) {
        try {
            String alg = algorithm.getValue();
            
            Object validationError = PasswordUtils.validatePBKDF2Iterations(iterations);
            if (validationError != null) {
                return validationError;
            }
            
            validationError = PasswordUtils.validatePBKDF2Algorithm(alg);
            if (validationError != null) {
                return validationError;
            }
            
            byte[] salt = PasswordUtils.generateRandomSalt();
            String saltBase64 = Base64.toBase64String(salt);
            
            String result = PasswordUtils.formatPBKDF2Salt(alg, iterations, saltBase64);
            
            return StringUtils.fromString(result);
        } catch (Exception e) {
            return CryptoUtils.createError("Error occurred while generating PBKDF2 salt: " + e.getMessage());
        }
    }

    /**
     * Generate PBKDF2 hash using the given parameters.
     *
     * @param password password to hash
     * @param salt salt to use
     * @param iterations number of iterations
     * @param algorithm HMAC algorithm to use (SHA1, SHA256, SHA512)
     * @return hash byte array
     * @throws NoSuchAlgorithmException if algorithm is not available
     * @throws InvalidKeySpecException if key specification is invalid
     */
    private static byte[] generatePBKDF2Hash(String password, byte[] salt, int iterations, String algorithm)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        
        String hmacAlgorithm = algorithm.toUpperCase(Locale.ROOT);
        String pbkdf2Algorithm;
        int keyLength;
        
        switch (hmacAlgorithm) {
            case "SHA1":
                pbkdf2Algorithm = "PBKDF2WithHmacSHA1";
                keyLength = 20; // SHA-1 produces 160-bit (20-byte) hash
                break;
            case "SHA256":
                pbkdf2Algorithm = "PBKDF2WithHmacSHA256";
                keyLength = 32; // SHA-256 produces 256-bit (32-byte) hash
                break;
            case "SHA512":
                pbkdf2Algorithm = "PBKDF2WithHmacSHA512";
                keyLength = 64; // SHA-512 produces 512-bit (64-byte) hash
                break;
            default:
                throw new NoSuchAlgorithmException("Unsupported algorithm: " + algorithm);
        }
        
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength * 8);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(pbkdf2Algorithm);
        return factory.generateSecret(spec).getEncoded();
    }
}

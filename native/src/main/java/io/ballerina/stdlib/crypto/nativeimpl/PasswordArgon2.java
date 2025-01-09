package io.ballerina.stdlib.crypto.nativeimpl;

import io.ballerina.runtime.api.utils.StringUtils;
import io.ballerina.runtime.api.values.BString;
import io.ballerina.stdlib.crypto.CryptoUtils;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.util.encoders.Base64;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class PasswordArgon2 {
    private static final int DEFAULT_ITERATIONS = 3;
    private static final int DEFAULT_MEMORY = 65536;  // 64MB in KB
    private static final int DEFAULT_PARALLELISM = 4;
    private static final int SALT_LENGTH = 16;
    private static final int HASH_LENGTH = 32;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    
    /**
     * Hash a password using Argon2id with default parameters.
     *
     * @param password The password to hash
     * @return Hashed password string or error
     */
    public static Object hashPasswordArgon2(BString password) {
        return hashPasswordArgon2(password, DEFAULT_ITERATIONS, DEFAULT_MEMORY, DEFAULT_PARALLELISM);
    }

    /**
     * Hash a password using Argon2id with custom parameters.
     *
     * @param password The password to hash
     * @param iterations Number of iterations
     * @param memory Memory usage in KB
     * @param parallelism Degree of parallelism
     * @return Hashed password string or error
     */
    public static Object hashPasswordArgon2(BString password, long iterations, long memory, long parallelism) {
        try {
            byte[] salt = new byte[SALT_LENGTH];
            SECURE_RANDOM.nextBytes(salt);

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

            // Format: $argon2id$v=19$m=memory,t=iterations,p=parallelism$salt$hash
            String saltBase64 = Base64.toBase64String(salt);
            String hashBase64 = Base64.toBase64String(hash);
            String result = String.format("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
                memory, iterations, parallelism, saltBase64, hashBase64);

            return StringUtils.fromString(result);
        } catch (Exception e) {
            return CryptoUtils.createError("Error occurred while hashing password with Argon2: " + e.getMessage());
        }
    }

    /**
     * Verify a password against a stored Argon2 hash.
     *
     * @param password The password to verify
     * @param hashedPassword The stored hash to verify against
     * @return Boolean indicating if the password matches
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

            // Parse parameters
            String[] params = parts[3].split(",");
            int memory = Integer.parseInt(params[0].substring(2));
            int iterations = Integer.parseInt(params[1].substring(2));
            int parallelism = Integer.parseInt(params[2].substring(2));

            byte[] salt = Base64.decode(parts[4]);
            byte[] originalHash = Base64.decode(parts[5]);

            // Generate new hash with same parameters
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

            return constantTimeArrayEquals(newHash, originalHash);
        } catch (Exception e) {
            return CryptoUtils.createError("Error occurred while verifying Argon2 password: " + e.getMessage());
        }
    }

    /**
     * Generate an Argon2 salt with default parameters.
     *
     * @return Generated salt string or error
     */
    public static Object generateSaltArgon2() {
        return generateSaltArgon2(DEFAULT_ITERATIONS, DEFAULT_MEMORY, DEFAULT_PARALLELISM);
    }

    /**
     * Generate an Argon2 salt with custom parameters.
     *
     * @param iterations Number of iterations
     * @param memory Memory usage in KB
     * @param parallelism Degree of parallelism
     * @return Generated salt string or error
     */
    public static Object generateSaltArgon2(long iterations, long memory, long parallelism) {
        try {
            byte[] salt = new byte[SALT_LENGTH];
            SECURE_RANDOM.nextBytes(salt);
            String saltBase64 = Base64.toBase64String(salt);
            
            String result = String.format("$argon2id$v=19$m=%d,t=%d,p=%d$%s",
                memory, iterations, parallelism, saltBase64);
            
            return StringUtils.fromString(result);
        } catch (Exception e) {
            return CryptoUtils.createError("Error occurred while generating Argon2 salt: " + e.getMessage());
        }
    }

        /**
     * Constant time array comparison to prevent timing attacks.
     */
    private static boolean constantTimeArrayEquals(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }
}

package io.ballerina.stdlib.crypto.nativeimpl;

import io.ballerina.runtime.api.utils.StringUtils;
import io.ballerina.runtime.api.values.BString;
import io.ballerina.stdlib.crypto.CryptoUtils;
import io.ballerina.stdlib.crypto.PasswordUtils;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.util.encoders.Base64;

import java.nio.charset.StandardCharsets;

public class PasswordArgon2 {
    private static final int DEFAULT_ITERATIONS = 3;
    private static final int DEFAULT_MEMORY = 65536;  // 64MB in KB
    private static final int DEFAULT_PARALLELISM = 4;
    private static final int HASH_LENGTH = 32;
    
    public static Object hashPasswordArgon2(BString password) {
        return hashPasswordArgon2(password, DEFAULT_ITERATIONS, DEFAULT_MEMORY, DEFAULT_PARALLELISM);
    }

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

    public static Object generateSaltArgon2() {
        return generateSaltArgon2(DEFAULT_ITERATIONS, DEFAULT_MEMORY, DEFAULT_PARALLELISM);
    }

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

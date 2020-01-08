package org.northcoder.passwordhasher;

import org.northcoder.password.SimplePasswordHandler;
import org.northcoder.password.PasswordHandler;
import org.junit.Test;
import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.Duration;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.codec.binary.Base64;

public class SimplePasswordHandlerTest {

    final PasswordHandler handler = new SimplePasswordHandler();
    
    public SimplePasswordHandlerTest() {
    }

    private final char[] pass1 = "password123456".toCharArray();
    private final int iterations1 = 350123;

    @Test
    public void testGenerateNewHashAndSalt1() {        
        final String salt = handler.generateSalt();
        final String hash = handler.generateHash(pass1,
                salt, iterations1);
        assertThat(hash).isNotNull();
        assertThat(Base64.isBase64(hash)).isTrue();
        assertThat(salt).isNotNull();
        assertThat(Base64.isBase64(salt)).isTrue();
    }

    @Test
    public void testPasswordIsValid() {
        // The original hash which was created when a user account & password
        // was created, or a password was reset, etc. We assume the salt, hash,
        // and iterations count are stored with the user ID (e.g. in a database).
        final String salt1 = handler.generateSalt();
        final String hash1 = handler.generateHash(pass1,
                salt1, iterations1);

        // When a user authenticates, we re-generate the hash from same password, 
        // salt and iterations count, as retrieved from the database:
        final boolean bool1 = handler.passwordIsValid(pass1,
                salt1, iterations1, hash1);
        assertThat(bool1).isTrue();

        // Extra test 1: Change the iterations count - hashes no longer match:
        final String hash2 = handler.generateHash(pass1,
                salt1, iterations1 + 1);
        boolean bool2 = handler.passwordIsValid(pass1,
                salt1, iterations1, hash2);
        assertThat(bool2).isFalse();

        // Extra test 2: Generate hash for same password (e.g. if 2 users have
        // chosen the same password - but they get allocated different salts):
        final String salt3 = handler.generateSalt();
        final String hash3 = handler.generateHash(pass1,
                salt3, iterations1);
        assertThat(salt3).isNotEqualTo(salt1);
        assertThat(hash3).isNotEqualTo(hash1);
    }

    @Test
    public void testGetAlgorithm() throws NoSuchAlgorithmException {
        // Check that the algorithm and provider are what we expect:
        assertThat(handler.getAlgorithmName()).isEqualTo("PBKDF2WithHmacSHA512");
        assertThat(handler.getProviderName()).isEqualTo("SunJCE");
    }

    @Test
    public void testTimeToValidate() {
        // Ensure it's not too slow and not too fast - otherwise, maybe
        // need to adjust the number of iterations. Should be fast enough to
        // give a good user experience, but slow enough to hamper brute-force
        // cracking attempts.
        int minMillis = 400;
        int maxMillis = 600;
        
        final String salt1 = handler.generateSalt();
        final String hash1 = handler.generateHash(pass1,
                salt1, iterations1);

        Instant t1 = Instant.now();
        final boolean bool1 = handler.passwordIsValid(pass1,
                salt1, iterations1, hash1);
        assertThat(bool1).isTrue();
        Instant t2 = Instant.now();
        double millis = Duration.between(t1, t2).getNano() / 1000000.0;
        assertThat(millis).isGreaterThan(minMillis);
        assertThat(millis).isLessThan(maxMillis);
    }

    @Test
    public void testBase64EncodeDecode() {  
        // We always store the hash and salt values as Base64-encoded strings.
        // Make sure our encode/decode functions work as expected:
        for (int i = 0; i < 10000; i++) {
            String data = RandomStringUtils.random(1000);
            String encoded = Base64.encodeBase64String(data.getBytes(UTF_8));
            String decoded = new String(Base64.decodeBase64(encoded), UTF_8);
            assertThat(decoded).isEqualTo(data);
        }
    }

}

package org.northcoder.password;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import static java.nio.charset.StandardCharsets.UTF_8;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.codec.binary.Base64;

/**
 * A password handler using the PBKDF2WithHmacSHA512 algorithm. It uses salts
 * which are 32-characters long.
 */
public class SimplePasswordHandler implements PasswordHandler {

    private static final String ALGORITHM = "PBKDF2WithHmacSHA512";

    @Override
    public String generateHash(final char[] password, final String salt, final int iterations) {
        final byte[] saltBytes = b64StringToData(salt).getBytes(UTF_8);
        final int keyLength = 512;
        final byte[] hashedPassBytes = hashPassword(password, saltBytes, keyLength, iterations);
        // To make storage simpler, the resulting hash is Base64-encoded:
        return Base64.encodeBase64String(hashedPassBytes);
    }

    @Override
    public String generateSalt() {
        // Strings are built from the set of printable Unicode characters.
        // To make storage simpler, the resulting salt is Base64-encoded:
        final int saltLength = 32;
        return dataToB64String(RandomStringUtils.secure().next(saltLength));
    }

    @Override
    public boolean passwordIsValid(final char[] password, final String storedSalt,
            final int storedIterations, final String storedHash) {
        return generateHash(password, storedSalt, storedIterations).equals(storedHash);
    }

    @Override
    public String getAlgorithmName() {
        return ALGORITHM;
    }

    @Override
    public String getProviderName() throws NoSuchAlgorithmException {
        final SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGORITHM);
        return skf.getProvider().getName();
    }

    private byte[] hashPassword(final char[] password, final byte[] salt,
            final int keyLength, final int iterations) {
        try {
            final SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGORITHM);
            final PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLength);
            return skf.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    private String dataToB64String(final String data) {
        return Base64.encodeBase64String(data.getBytes(UTF_8));
    }

    private String b64StringToData(final String b64String) {
        return new String(Base64.decodeBase64(b64String), UTF_8);
    }

}

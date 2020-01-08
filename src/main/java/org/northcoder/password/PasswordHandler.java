package org.northcoder.password;

import java.security.NoSuchAlgorithmException;

/**
 * Supports the creation of a password hash, using a unique salt; and also the
 * verification of existing passwords during authentication/sign-on/log-in.
 */
public interface PasswordHandler {

    /**
     * Generates a password hash - for example, for a new user account, or when
     * a password is reset.
     *
     * @param password The password to be hashed. This value must never be
     * persisted or stored anywhere. Client code which manipulates the password
     * (e.g. in strings received from HTML forms) should be nulled as soon as
     * possible to assist with prompt garbage collection. Passwords should be
     * converted from strings to char arrays, for added security.
     * @param salt Each password should be allocated its own unique salt, which
     * should be stored with the hash. The salt is Base64-encoded to facilitate
     * storage as text.
     * @param iterations The number of times the hashing algorithm will be
     * recursively invoked. This value will typically be set as a system-wide
     * value elsewhere (such as in a properties file). However, the specific
     * value used when hashing a password needs to be stored alongside the hash
     * (and salt). This is because the system-wide value can be adjusted over
     * time, to tune the speed of the hashing process. Hashing should be fast
     * enough to provide a reasonable user experience, but slow enough to hamper
     * brute-force cracking attempts.
     * @return The hash for the password, formatted as a Base64-encoded string,
     * to facilitate storage as text.
     */
    public String generateHash(
            final char[] password,
            final String salt,
            final int iterations);

    /**
     * Generates a random salt, to be used when hashing a new password. A client
     * will typically call this method first, and then use the salt when calling
     * the {@link #generateHash(char[], java.lang.String, int)} method.
     *
     * @return The salt is returned as a Base64-encoded string, to facilitate
     * storage as text.
     */
    public String generateSalt();

    /**
     * Used to verify a user's password during the authentication/log-in/sign-on
     * process. The provided password is hashed using the original salt and
     * iterations count. The resulting hash is compared to the original hash
     * value. If the values are the same, the user has provided the correct
     * password.
     *
     * @param password The value provided by the user during
     * login/authentication.
     * @param storedSalt The salt (Base64-encoded) used when the user's password
     * was originally created.
     * @param storedIterations The number of hashing iterations used when the
     * user's password was originally created.
     * @param storedHash The original hash value which was computed when the
     * user's password was originally created.
     * @return True if the password is verified; false otherwise.
     */
    public boolean passwordIsValid(
            final char[] password,
            final String storedSalt,
            final int storedIterations,
            final String storedHash);

    /**
     * Documents the algorithm used for password hashing. Can optionally be
     * stored with the password hash.
     *
     * @return The algorithm's name, for example PBKDF2WithHmacSHA512.
     */
    public String getAlgorithmName();

    /**
     * Documents the hashing algorithm's provider (creator). Can optionally be
     * stored with the password hash.
     *
     * @return The provider's name, for example SunJCE.
     * @throws NoSuchAlgorithmException If an invalid algorithm name is
     * provided.
     */
    public String getProviderName() throws NoSuchAlgorithmException;

}

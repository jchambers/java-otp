/* Copyright (c) 2016 Jon Chambers
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE. */

package com.eatthepath.otp;

import javax.crypto.Mac;
import javax.crypto.ShortBufferException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;

/**
 * Generates HMAC-based one-time passwords (HOTP) as specified in
 * <a href="https://tools.ietf.org/html/rfc4226">RFC&nbsp;4226</a>. {@code HmacOneTimePasswordGenerator} instances are
 * thread-safe and may be shared between threads.
 *
 * @author <a href="https://github.com/jchambers">Jon Chambers</a>
 */
public class HmacOneTimePasswordGenerator {
    private final String algorithm;
    private final int passwordLength;
    private final int modDivisor;
    private final String formatString;

    /**
     * The default length, in decimal digits, for one-time passwords.
     */
    public static final int DEFAULT_PASSWORD_LENGTH = 6;

    /**
     * The HMAC algorithm specified by the HOTP standard.
     */
    static final String HOTP_HMAC_ALGORITHM = "HmacSHA1";

    /**
     * Creates a new HMAC-based one-time password (HOTP) generator using a default password length
     * ({@value com.eatthepath.otp.HmacOneTimePasswordGenerator#DEFAULT_PASSWORD_LENGTH} digits).
     */
    public HmacOneTimePasswordGenerator() {
        this(DEFAULT_PASSWORD_LENGTH);
    }

    /**
     * Creates a new HMAC-based one-time password (HOTP) generator using the given password length.
     *
     * @param passwordLength the length, in decimal digits, of the one-time passwords to be generated; must be between
     * 6 and 8, inclusive
     */
    public HmacOneTimePasswordGenerator(final int passwordLength) {
        // Every implementation of the Java platform is required to support the HmacSHA1 Mac algorithm, so we don't need
        // to check for a `NoSuchAlgorithm` exception
        this.algorithm = HOTP_HMAC_ALGORITHM;
        this.modDivisor = getModDivisor(passwordLength);
        this.formatString = getFormatString(passwordLength);
        this.passwordLength = passwordLength;
    }

    /**
     * Creates a new HMAC-based one-time password generator using the given password length and algorithm. Note that
     * <a href="https://tools.ietf.org/html/rfc4226">RFC&nbsp;4226</a> specifies that HOTP must always use HMAC-SHA1 as
     * an algorithm, but derived one-time password systems like TOTP may allow for other algorithms.
     *
     * @param passwordLength the length, in decimal digits, of the one-time passwords to be generated; must be between
     * 6 and 8, inclusive
     * @param algorithm the name of the {@link javax.crypto.Mac} algorithm to use when generating passwords; note that
     * HOTP only allows for {@value com.eatthepath.otp.HmacOneTimePasswordGenerator#HOTP_HMAC_ALGORITHM}, but derived
     * standards like TOTP may allow for other algorithms
     *
     * @throws NoSuchAlgorithmException if the given algorithm is not supported by the underlying JRE
     */
    HmacOneTimePasswordGenerator(final int passwordLength, final String algorithm) throws NoSuchAlgorithmException {
        // Fail fast if the requested algorithm isn't supported
        final Mac mac = Mac.getInstance(algorithm);

        assert mac.getMacLength() >= 8;

        this.algorithm = algorithm;

        this.modDivisor = getModDivisor(passwordLength);
        this.formatString = getFormatString(passwordLength);
        this.passwordLength = passwordLength;
    }

    private static int getModDivisor(final int passwordLength) {
        switch (passwordLength) {
            case 6: {
                return 1_000_000;
            }

            case 7: {
                return 10_000_000;
            }

            case 8: {
                return 100_000_000;
            }

            default: {
                throw new IllegalArgumentException("Password length must be between 6 and 8 digits.");
            }
        }
    }

    private static String getFormatString(final int passwordLength) {
        switch (passwordLength) {
            case 6: {
                return "%06d";
            }

            case 7: {
                return "%07d";
            }

            case 8: {
                return "%08d";
            }

            default: {
                throw new IllegalArgumentException("Password length must be between 6 and 8 digits.");
            }
        }
    }

    /**
     * Generates a one-time password using the given key and counter value.
     *
     * @param key the key to be used to generate the password
     * @param counter the counter value for which to generate the password
     *
     * @return an integer representation of a one-time password; callers will need to format the password for display
     * on their own
     *
     * @throws InvalidKeyException if the given key is inappropriate for initializing the {@link Mac} for this generator
     */
    public int generateOneTimePassword(final Key key, final long counter) throws InvalidKeyException {
        final Mac mac = getMac();
        final ByteBuffer buffer = ByteBuffer.allocate(mac.getMacLength());

        buffer.putLong(0, counter);

        try {
            final byte[] array = buffer.array();

            mac.init(key);
            mac.update(array, 0, 8);
            mac.doFinal(array, 0);
        } catch (final ShortBufferException e) {
            // We allocated the buffer's backing array to match the MAC length, so this should never happen.
            throw new AssertionError("Generated MAC longer than self-reported MAC length", e);
        }

        final int offset = buffer.get(buffer.capacity() - 1) & 0x0f;
        return (buffer.getInt(offset) & 0x7fff_ffff) % this.modDivisor;
    }

    private Mac getMac() {
        try {
            return Mac.getInstance(algorithm);
        } catch (final NoSuchAlgorithmException e) {
            // We checked that we can instantiate a Mac with the given algorithm at construction time
            throw new AssertionError("Previously-supported algorithm no longer found", e);
        }
    }

    /**
     * Generates a one-time password using the given key and counter value and formats it as a string using the system
     * default locale.
     *
     * @param key the key to be used to generate the password
     * @param counter the counter value for which to generate the password
     *
     * @return a string representation of a one-time password
     *
     * @throws InvalidKeyException if the given key is inappropriate for initializing the {@link Mac} for this generator
     *
     * @see Locale#getDefault()
     */
    public String generateOneTimePasswordString(final Key key, final long counter) throws InvalidKeyException {
        return this.generateOneTimePasswordString(key, counter, Locale.getDefault());
    }

    /**
     * Generates a one-time password using the given key and counter value and formats it as a string using the given
     * locale.
     *
     * @param key the key to be used to generate the password
     * @param counter the counter value for which to generate the password
     * @param locale the locale to apply during formatting
     *
     * @return a string representation of a one-time password
     *
     * @throws InvalidKeyException if the given key is inappropriate for initializing the {@link Mac} for this generator
     */
    public String generateOneTimePasswordString(final Key key, final long counter, final Locale locale) throws InvalidKeyException {
        return this.formatOneTimePassword(generateOneTimePassword(key, counter), locale);
    }

    /**
     * Checks whether a given one-time password matches the one-time password generated for the given key and counter
     * value. Note that this method simply checks equality of two one-time passwords; incrementing expected counter
     * values, throttling/rate-limiting, counter resynchronization, and so one are all beyond the scope of this method.
     *
     * @param key the key to be used to generate the password
     * @param counter the counter value for which to generate the password
     * @param oneTimePassword the user-provided one-time password to check against the generated one-time password
     *
     * @return {@code true} if and only if the given one-time password matches the one-time password generated for the
     * given key and counter value; one-time password strings match if they have the correct number of digits (see
     * {@link #getPasswordLength()}), can be parsed as an integer, and that integer matches the one-time password
     * generated for the given key and counter value
     *
     * @throws InvalidKeyException if the given key is inappropriate for initializing the {@link Mac} for this generator
     * @throws NullPointerException if the given one-time password is {@code null}
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4226#section-7">HOTP: An HMAC-Based One-Time Password Algorithm (RFC 4226) - Security Requirements</a>
     */
    public boolean validateOneTimePassword(final Key key, final long counter, final String oneTimePassword) throws InvalidKeyException {
        if (oneTimePassword == null) {
            throw new NullPointerException("One-time password must not be null");
        }

        // We COULD return early if the length doesn't match, but that could allow an attacker to learn the expected
        // passowrd length by observing execution time. Arguably, the expected password length isn't a secret, but we
        // can avoid revealing it here and choose to do so.
        final boolean lengthMatches = oneTimePassword.length() == this.passwordLength;

        try {
            final boolean passwordMatches = validateOneTimePassword(key, counter, Integer.parseInt(oneTimePassword));

            // Again, this construction may seem a little odd, but the goal is to make sure this check happens in
            // constant time relative to any secret data or internal state. `&` is a constant-time operation while `&&`
            // can short-circuit. This construction means we evaluate both criteria and don't return early if the length
            // of the given one-time password was incorrect.
            return lengthMatches & passwordMatches;
        } catch (final NumberFormatException e) {
            return false;
        }
    }

    /**
     * Checks whether a given one-time password matches the one-time password generated for the given key and counter
     * value. Note that this method simply checks equality of two one-time passwords; incrementing expected counter
     * values, throttling/rate-limiting, counter resynchronization, and so one are all beyond the scope of this method.
     *
     * @param key the key to be used to generate the password
     * @param counter the counter value for which to generate the password
     * @param oneTimePassword the user-provided one-time password to check against the generated one-time password
     *
     * @return {@code true} if and only if the given one-time password matches the one-time password generated for the
     * given key and counter value
     *
     * @throws InvalidKeyException if the given key is inappropriate for initializing the {@link Mac} for this generator
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4226#section-7">HOTP: An HMAC-Based One-Time Password Algorithm (RFC 4226) - Security Requirements</a>
     */
    public boolean validateOneTimePassword(final Key key, final long counter, final int oneTimePassword) throws InvalidKeyException {
        return generateOneTimePassword(key, counter) == oneTimePassword;
    }

    /**
     * Formats a one-time password as a fixed-length string using the given locale.
     *
     * @param oneTimePassword the one-time password to format as a string
     * @param locale the locale to apply during formatting
     *
     * @return a string representation of the given one-time password
     */
    String formatOneTimePassword(final int oneTimePassword, final Locale locale) {
        return String.format(locale, formatString, oneTimePassword);
    }

    /**
     * Returns the length, in decimal digits, of passwords produced by this generator.
     *
     * @return the length, in decimal digits, of passwords produced by this generator
     */
    public int getPasswordLength() {
        return this.passwordLength;
    }

    /**
     * Returns the name of the HMAC algorithm used by this generator.
     *
     * @return the name of the HMAC algorithm used by this generator
     */
    public String getAlgorithm() {
        return this.algorithm;
    }
}

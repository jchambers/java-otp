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
    private final Mac prototypeMac;
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
        this(passwordLength, HOTP_HMAC_ALGORITHM);
    }

    /**
     * <p>Creates a new HMAC-based one-time password generator using the given password length and algorithm. Note that
     * <a href="https://tools.ietf.org/html/rfc4226">RFC&nbsp;4226</a> specifies that HOTP must always use HMAC-SHA1 as
     * an algorithm, but derived one-time password systems like TOTP may allow for other algorithms.</p>
     *
     * @param passwordLength the length, in decimal digits, of the one-time passwords to be generated; must be between
     * 6 and 8, inclusive
     * @param algorithm the name of the {@link javax.crypto.Mac} algorithm to use when generating passwords; note that
     * HOTP only allows for {@value com.eatthepath.otp.HmacOneTimePasswordGenerator#HOTP_HMAC_ALGORITHM}, but derived
     * standards like TOTP may allow for other algorithms
     *
     * @throws UncheckedNoSuchAlgorithmException if the given algorithm is not supported by the underlying JRE
     */
    HmacOneTimePasswordGenerator(final int passwordLength, final String algorithm) throws UncheckedNoSuchAlgorithmException {
        try {
            this.prototypeMac = Mac.getInstance(algorithm);
        } catch (final NoSuchAlgorithmException e) {
            throw new UncheckedNoSuchAlgorithmException(e);
        }

        switch (passwordLength) {
            case 6: {
                this.modDivisor = 1_000_000;
                this.formatString = "%06d";
                break;
            }

            case 7: {
                this.modDivisor = 10_000_000;
                this.formatString = "%07d";
                break;
            }

            case 8: {
                this.modDivisor = 100_000_000;
                this.formatString = "%08d";
                break;
            }

            default: {
                throw new IllegalArgumentException("Password length must be between 6 and 8 digits.");
            }
        }

        this.passwordLength = passwordLength;
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
            // We allocated the buffer to (at least) match the size of the MAC length at construction time, so this
            // should never happen.
            throw new RuntimeException(e);
        }

        final int offset = buffer.get(buffer.capacity() - 1) & 0x0f;
        return (buffer.getInt(offset) & 0x7fffffff) % this.modDivisor;
    }

    private Mac getMac() {
        try {
            // Cloning is generally cheaper than `Mac.getInstance`, but isn't GUARANTEED to be supported.
            return (Mac) this.prototypeMac.clone();
        } catch (CloneNotSupportedException e) {
            try {
                return Mac.getInstance(this.prototypeMac.getAlgorithm());
            } catch (final NoSuchAlgorithmException ex) {
                // This should be impossible; we're getting the algorithm from a Mac that already exists, and so the
                // algorithm must be supported.
                throw new RuntimeException(ex);
            }
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
        return this.prototypeMac.getAlgorithm();
    }
}

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
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

/**
 * <p>Generates HMAC-based one-time passwords (HOTP) as specified in
 * <a href="https://tools.ietf.org/html/rfc4226">RFC&nbsp;4226</a>.</p>
 *
 * <p>{@code HmacOneTimePasswordGenerator} instances are thread-safe and may be shared between threads.</p>
 *
 * @author <a href="https://github.com/jchambers">Jon Chambers</a>
 */
public class HmacOneTimePasswordGenerator {
    private final Mac mac;
    private final int passwordLength;

    private final byte[] buffer;
    private final int modDivisor;

    /**
     * The default length, in decimal digits, for one-time passwords.
     */
    public static final int DEFAULT_PASSWORD_LENGTH = 6;

    /**
     * The HMAC algorithm specified by the HOTP standard.
     */
    public static final String HOTP_HMAC_ALGORITHM = "HmacSHA1";

    /**
     * Creates a new HMAC-based one-time password (HOTP) generator using a default password length
     * ({@value com.eatthepath.otp.HmacOneTimePasswordGenerator#DEFAULT_PASSWORD_LENGTH} digits).
     *
     * @throws NoSuchAlgorithmException if the underlying JRE doesn't support the
     * {@value com.eatthepath.otp.HmacOneTimePasswordGenerator#HOTP_HMAC_ALGORITHM} algorithm, which should never
     * happen except in cases of serious misconfiguration
     */
    public HmacOneTimePasswordGenerator() throws NoSuchAlgorithmException {
        this(DEFAULT_PASSWORD_LENGTH);
    }

    /**
     * Creates a new HMAC-based one-time password (HOTP) generator using the given password length.
     *
     * @param passwordLength the length, in decimal digits, of the one-time passwords to be generated; must be between
     * 6 and 8, inclusive
     *
     * @throws NoSuchAlgorithmException if the underlying JRE doesn't support the
     * {@value com.eatthepath.otp.HmacOneTimePasswordGenerator#HOTP_HMAC_ALGORITHM} algorithm, which should never
     * happen except in cases of serious misconfiguration
     */
    public HmacOneTimePasswordGenerator(final int passwordLength) throws NoSuchAlgorithmException {
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
     * @throws NoSuchAlgorithmException if the given algorithm is not supported by the underlying JRE
     */
    protected HmacOneTimePasswordGenerator(final int passwordLength, final String algorithm) throws NoSuchAlgorithmException {
        this.mac = Mac.getInstance(algorithm);

        switch (passwordLength) {
            case 6: {
                this.modDivisor = 1_000_000;
                break;
            }

            case 7: {
                this.modDivisor = 10_000_000;
                break;
            }

            case 8: {
                this.modDivisor = 100_000_000;
                break;
            }

            default: {
                throw new IllegalArgumentException("Password length must be between 6 and 8 digits.");
            }
        }

        this.passwordLength = passwordLength;
        this.buffer = new byte[this.mac.getMacLength()];
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
    public synchronized int generateOneTimePassword(final Key key, final long counter) throws InvalidKeyException {
        this.mac.init(key);

        this.buffer[0] = (byte) ((counter & 0xff00000000000000L) >>> 56);
        this.buffer[1] = (byte) ((counter & 0x00ff000000000000L) >>> 48);
        this.buffer[2] = (byte) ((counter & 0x0000ff0000000000L) >>> 40);
        this.buffer[3] = (byte) ((counter & 0x000000ff00000000L) >>> 32);
        this.buffer[4] = (byte) ((counter & 0x00000000ff000000L) >>> 24);
        this.buffer[5] = (byte) ((counter & 0x0000000000ff0000L) >>> 16);
        this.buffer[6] = (byte) ((counter & 0x000000000000ff00L) >>> 8);
        this.buffer[7] = (byte)  (counter & 0x00000000000000ffL);

        this.mac.update(this.buffer, 0, 8);

        try {
            this.mac.doFinal(this.buffer, 0);
        } catch (final ShortBufferException e) {
            // We allocated the buffer to (at least) match the size of the MAC length at construction time, so this
            // should never happen.
            throw new RuntimeException(e);
        }

        final int offset = this.buffer[this.buffer.length - 1] & 0x0f;

        return ((this.buffer[offset]     & 0x7f) << 24 |
                (this.buffer[offset + 1] & 0xff) << 16 |
                (this.buffer[offset + 2] & 0xff) <<  8 |
                (this.buffer[offset + 3] & 0xff)) %
                this.modDivisor;
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
        return this.mac.getAlgorithm();
    }
}

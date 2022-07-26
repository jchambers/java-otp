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
import java.security.InvalidKeyException;
import java.security.Key;
import java.time.Duration;
import java.time.Instant;
import java.util.Locale;

/**
 * <p>Generates time-based one-time passwords (TOTP) as specified in
 * <a href="https://tools.ietf.org/html/rfc6238">RFC&nbsp;6238</a>.</p>
 *
 * <p>{@code TimeBasedOneTimePasswordGenerator} instances are thread-safe and may be shared between threads. Note that
 * the {@link #generateOneTimePassword(Key, Instant)} method (and its relatives) are {@code synchronized}; in
 * multi-threaded applications that make heavy use of a shared {@code TimeBasedOneTimePasswordGenerator} instance,
 * synchronization may become a performance bottleneck. In that case, callers may benefit from using one
 * {@code TimeBasedOneTimePasswordGenerator} instance per thread (for example, with a {@link ThreadLocal}).</p>
 *
 * @author <a href="https://github.com/jchambers">Jon Chambers</a>
 */
public class TimeBasedOneTimePasswordGenerator {
    private final HmacOneTimePasswordGenerator hotp;
    private final Duration timeStep;

    /**
     * The default time-step for a time-based one-time password generator (30 seconds).
     */
    public static final Duration DEFAULT_TIME_STEP = Duration.ofSeconds(30);

    /**
     * A string identifier for the HMAC-SHA1 algorithm; HMAC-SHA1 is the default algorithm for TOTP.
     */
    public static final String TOTP_ALGORITHM_HMAC_SHA1 = "HmacSHA1";

    /**
     * A string identifier for the HMAC-SHA256 algorithm.
     */
    @SuppressWarnings("unused")
    public static final String TOTP_ALGORITHM_HMAC_SHA256 = "HmacSHA256";

    /**
     * A string identifier for the HMAC-SHA512 algorithm.
     */
    @SuppressWarnings("unused")
    public static final String TOTP_ALGORITHM_HMAC_SHA512 = "HmacSHA512";

    /**
     * Constructs a new time-based one-time password generator with a default time-step (30 seconds), password length
     * ({@value com.eatthepath.otp.HmacOneTimePasswordGenerator#DEFAULT_PASSWORD_LENGTH} decimal digits), and HMAC
     * algorithm ({@value com.eatthepath.otp.HmacOneTimePasswordGenerator#HOTP_HMAC_ALGORITHM}).
     */
    public TimeBasedOneTimePasswordGenerator() {
        this(DEFAULT_TIME_STEP);
    }

    /**
     * Constructs a new time-based one-time password generator with the given time-step and a default password length
     * ({@value com.eatthepath.otp.HmacOneTimePasswordGenerator#DEFAULT_PASSWORD_LENGTH} decimal digits) and HMAC
     * algorithm ({@value com.eatthepath.otp.HmacOneTimePasswordGenerator#HOTP_HMAC_ALGORITHM}).
     *
     * @param timeStep the time-step for this generator
     */
    public TimeBasedOneTimePasswordGenerator(final Duration timeStep) {
        this(timeStep, HmacOneTimePasswordGenerator.DEFAULT_PASSWORD_LENGTH);
    }

    /**
     * Constructs a new time-based one-time password generator with the given time-step and password length and a
     * default HMAC algorithm ({@value com.eatthepath.otp.HmacOneTimePasswordGenerator#HOTP_HMAC_ALGORITHM}).
     *
     * @param timeStep the time-step for this generator
     * @param passwordLength the length, in decimal digits, of the one-time passwords to be generated; must be between
     * 6 and 8, inclusive
     */
    public TimeBasedOneTimePasswordGenerator(final Duration timeStep, final int passwordLength) {
        this(timeStep, passwordLength, TOTP_ALGORITHM_HMAC_SHA1);
    }

    /**
     * Constructs a new time-based one-time password generator with the given time-step, password length, and HMAC
     * algorithm.
     *
     * @param timeStep the time-step for this generator
     * @param passwordLength the length, in decimal digits, of the one-time passwords to be generated; must be between
     * 6 and 8, inclusive
     * @param algorithm the name of the {@link javax.crypto.Mac} algorithm to use when generating passwords; TOTP allows
     * for {@value #TOTP_ALGORITHM_HMAC_SHA1}, {@value #TOTP_ALGORITHM_HMAC_SHA256}, and
     * {@value #TOTP_ALGORITHM_HMAC_SHA512}
     *
     * @throws UncheckedNoSuchAlgorithmException if the given algorithm is {@value #TOTP_ALGORITHM_HMAC_SHA512} and the
     * JVM does not support that algorithm; all JVMs are required to support {@value #TOTP_ALGORITHM_HMAC_SHA1} and
     * {@value #TOTP_ALGORITHM_HMAC_SHA256}, but are not required to support {@value #TOTP_ALGORITHM_HMAC_SHA512}
     *
     * @see #TOTP_ALGORITHM_HMAC_SHA1
     * @see #TOTP_ALGORITHM_HMAC_SHA256
     * @see #TOTP_ALGORITHM_HMAC_SHA512
     */
    public TimeBasedOneTimePasswordGenerator(final Duration timeStep, final int passwordLength, final String algorithm)
            throws UncheckedNoSuchAlgorithmException {

        this.hotp = new HmacOneTimePasswordGenerator(passwordLength, algorithm);
        this.timeStep = timeStep;
    }

    /**
     * Generates a one-time password using the given key and timestamp.
     *
     * @param key the key to be used to generate the password
     * @param timestamp the timestamp for which to generate the password
     *
     * @return an integer representation of a one-time password; callers will need to format the password for display
     * on their own
     *
     * @throws InvalidKeyException if the given key is inappropriate for initializing the {@link Mac} for this generator
     */
    public int generateOneTimePassword(final Key key, final Instant timestamp) throws InvalidKeyException {
        return this.hotp.generateOneTimePassword(key, timestamp.toEpochMilli() / this.timeStep.toMillis());
    }

    /**
     * Generates a one-time password using the given key and timestamp and formats it as a string with the system
     * default locale.
     *
     * @param key the key to be used to generate the password
     * @param timestamp the timestamp for which to generate the password
     *
     * @return a string representation of a one-time password
     *
     * @throws InvalidKeyException if the given key is inappropriate for initializing the {@link Mac} for this generator
     *
     * @see Locale#getDefault()
     */
    public String generateOneTimePasswordString(final Key key, final Instant timestamp) throws InvalidKeyException {
        return this.generateOneTimePasswordString(key, timestamp, Locale.getDefault());
    }

    /**
     * Generates a one-time password using the given key and timestamp and formats it as a string with the given locale.
     *
     * @param key the key to be used to generate the password
     * @param timestamp the timestamp for which to generate the password
     * @param locale the locale to apply during formatting
     *
     * @return a string representation of a one-time password
     *
     * @throws InvalidKeyException if the given key is inappropriate for initializing the {@link Mac} for this generator
     */
    public String generateOneTimePasswordString(final Key key, final Instant timestamp, final Locale locale) throws InvalidKeyException {
        return this.hotp.formatOneTimePassword(this.generateOneTimePassword(key, timestamp), locale);
    }

    /**
     * Returns the time step used by this generator.
     *
     * @return the time step used by this generator
     */
    public Duration getTimeStep() {
        return this.timeStep;
    }

    /**
     * Returns the length, in decimal digits, of passwords produced by this generator.
     *
     * @return the length, in decimal digits, of passwords produced by this generator
     */
    public int getPasswordLength() {
        return this.hotp.getPasswordLength();
    }

    /**
     * Returns the name of the HMAC algorithm used by this generator.
     *
     * @return the name of the HMAC algorithm used by this generator
     */
    public String getAlgorithm() {
        return this.hotp.getAlgorithm();
    }
}

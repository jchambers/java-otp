package com.eatthepath.otp;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import javax.crypto.Mac;

/**
 * Generates time-based one-time passwords (TOTP) as specified in
 * <a href="https://tools.ietf.org/html/rfc6238">RFC&nbsp;6238</a>.
 *
 * @author <a href="https://github.com/jchambers">Jon Chambers</a>
 */
public class TimeBasedOneTimePasswordGenerator {
    private final HmacOneTimePasswordGenerator hmacOneTimePasswordGenerator;
    private final long timeStepMillis;

    /**
     * Constructs a new time=based one-time password generator with a default time-step (30 seconds), password length
     * ({@value com.eatthepath.otp.HmacOneTimePasswordGenerator#DEFAULT_PASSWORD_LENGTH} decimal digits), and HMAC
     * algorithm (HMAC-SHA1).
     *
     * @throws NoSuchAlgorithmException if the underlying JRE doesn't support HMAC-SHA1, which should never happen
     * except in cases of serious misconfiguration
     */
    public TimeBasedOneTimePasswordGenerator() throws NoSuchAlgorithmException {
        this(30, TimeUnit.SECONDS);
    }

    /**
     * Constructs a new time=based one-time password generator with the given time-step and a default password length
     * ({@value com.eatthepath.otp.HmacOneTimePasswordGenerator#DEFAULT_PASSWORD_LENGTH} decimal digits) and HMAC
     * algorithm (HMAC-SHA1).
     *
     * @param timeStep the magnitude of the time-step for this generator
     * @param timeStepUnit the units for the the given time step
     *
     * @throws NoSuchAlgorithmException if the underlying JRE doesn't support HMAC-SHA1, which should never happen
     * except in cases of serious misconfiguration
     */
    public TimeBasedOneTimePasswordGenerator(final long timeStep, final TimeUnit timeStepUnit) throws NoSuchAlgorithmException {
        this(timeStep, timeStepUnit, HmacOneTimePasswordGenerator.DEFAULT_PASSWORD_LENGTH);
    }

    /**
     * Constructs a new time=based one-time password generator with the given time-step and password length and a
     * default HMAC algorithm (HMAC-SHA1).
     *
     * @param timeStep the magnitude of the time-step for this generator
     * @param timeStepUnit the units for the the given time step
     * @param passwordLength the length, in decimal digits, of the one-time passwords to be generated; must be between
     * 6 and 8, inclusive
     *
     * @throws NoSuchAlgorithmException if the underlying JRE doesn't support HMAC-SHA1, which should never happen
     * except in cases of serious misconfiguration
     */
    public TimeBasedOneTimePasswordGenerator(final long timeStep, final TimeUnit timeStepUnit, final int passwordLength) throws NoSuchAlgorithmException {
        this(timeStep, timeStepUnit, passwordLength, HmacOneTimePasswordGenerator.ALGORITHM_HMAC_SHA1);
    }

    /**
     * Constructs a new time=based one-time password generator with the given time-step, password length, and HMAC
     * algorithm.
     *
     * @param timeStep the magnitude of the time-step for this generator
     * @param timeStepUnit the units for the the given time step
     * @param passwordLength the length, in decimal digits, of the one-time passwords to be generated; must be between
     * 6 and 8, inclusive
     * @param algorithm the name of the {@link javax.crypto.Mac} algorithm to use when generating passwords; TOTP allows
     * for {@value com.eatthepath.otp.HmacOneTimePasswordGenerator#ALGORITHM_HMAC_SHA1},
     * {@value com.eatthepath.otp.HmacOneTimePasswordGenerator#ALGORITHM_HMAC_SHA256}, and
     * {@value com.eatthepath.otp.HmacOneTimePasswordGenerator#ALGORITHM_HMAC_SHA512}
     *
     * @throws NoSuchAlgorithmException if the underlying JRE doesn't support HMAC-SHA1, which should never happen
     * except in cases of serious misconfiguration
     *
     * @see com.eatthepath.otp.HmacOneTimePasswordGenerator#ALGORITHM_HMAC_SHA1
     * @see com.eatthepath.otp.HmacOneTimePasswordGenerator#ALGORITHM_HMAC_SHA256
     * @see com.eatthepath.otp.HmacOneTimePasswordGenerator#ALGORITHM_HMAC_SHA512
     */
    public TimeBasedOneTimePasswordGenerator(final long timeStep, final TimeUnit timeStepUnit, final int passwordLength, final String algorithm) throws NoSuchAlgorithmException {
        this.timeStepMillis = timeStepUnit.toMillis(timeStep);
        this.hmacOneTimePasswordGenerator = new HmacOneTimePasswordGenerator(passwordLength, algorithm);
    }

    /**
     * Generates a one-time password using the given key and timestamp.
     *
     * @param key a secret key to be used to generate the password
     * @param timestamp the timestamp for which to generate the password
     *
     * @return an integer representation of a one-time password; callers will need to format the password for display
     * on their own
     *
     * @throws InvalidKeyException if the given key is inappropriate for initializing the {@link Mac} for this generator
     */
    public int generateOneTimePassword(final Key key, final Date timestamp) throws InvalidKeyException {
        return this.hmacOneTimePasswordGenerator.generateOneTimePassword(key, timestamp.getTime() / this.timeStepMillis);
    }
}

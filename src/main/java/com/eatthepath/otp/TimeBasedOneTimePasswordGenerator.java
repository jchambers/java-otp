package com.eatthepath.otp;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.concurrent.TimeUnit;

public class TimeBasedOneTimePasswordGenerator {
    private final HmacOneTimePasswordGenerator hmacOneTimePasswordGenerator;
    private final long timeStepMillis;

    public TimeBasedOneTimePasswordGenerator(final long timeStep, final TimeUnit timeStepUnit) throws NoSuchAlgorithmException {
        this(timeStep, timeStepUnit, HmacOneTimePasswordGenerator.DEFAULT_PASSWORD_LENGTH);
    }

    public TimeBasedOneTimePasswordGenerator(final long timeStep, final TimeUnit timeStepUnit, final int passwordLength) throws NoSuchAlgorithmException {
        this(timeStep, timeStepUnit, passwordLength, HmacOneTimePasswordGenerator.ALGORITHM_HMAC_SHA1);
    }

    public TimeBasedOneTimePasswordGenerator(final long timeStep, final TimeUnit timeStepUnit, final int passwordLength, final String algorithm) throws NoSuchAlgorithmException {
        this.timeStepMillis = timeStepUnit.toMillis(timeStep);
        this.hmacOneTimePasswordGenerator = new HmacOneTimePasswordGenerator(passwordLength, algorithm);
    }

    public int generateOneTimePassword(final Key key, final Date time) throws InvalidKeyException {
        return this.hmacOneTimePasswordGenerator.generateOneTimePassword(key, time.getTime() / this.timeStepMillis);
    }
}

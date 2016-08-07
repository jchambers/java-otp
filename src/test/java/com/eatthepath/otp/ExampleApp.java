package com.eatthepath.otp;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import javax.crypto.KeyGenerator;

public class ExampleApp {
    public static void main(final String[] args) throws NoSuchAlgorithmException, InvalidKeyException {
        final TimeBasedOneTimePasswordGenerator totp = new TimeBasedOneTimePasswordGenerator();

        final Key secretKey;
        {
            final KeyGenerator keyGenerator = KeyGenerator.getInstance(totp.getAlgorithm());
            keyGenerator.init(20);

            secretKey = keyGenerator.generateKey();
        }

        final Date now = new Date();
        final Date later = new Date(now.getTime() + TimeUnit.SECONDS.toMillis(30));

        System.out.format("Current password: %06d\n", totp.generateOneTimePassword(secretKey, now));
        System.out.format("Future password:  %06d\n", totp.generateOneTimePassword(secretKey, later));
    }
}

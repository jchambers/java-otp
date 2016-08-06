package com.eatthepath.otp;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;

public class HmacOneTimePasswordGenerator {
    private final int modDivisor;
    private final String algorithm;

    public static final int DEFAULT_PASSWORD_LENGTH = 6;

    public static final String ALGORITHM_HMAC_SHA1 = "HmacSHA1";
    public static final String ALGORITHM_HMAC_SHA256 = "HmacSHA256";
    public static final String ALGORITHM_HMAC_SHA512 = "HmacSHA512";

    public HmacOneTimePasswordGenerator() throws NoSuchAlgorithmException {
        this(DEFAULT_PASSWORD_LENGTH);
    }

    public HmacOneTimePasswordGenerator(final int passwordLength) throws NoSuchAlgorithmException {
        this(passwordLength, ALGORITHM_HMAC_SHA1);
    }

    public HmacOneTimePasswordGenerator(final int passwordLength, final String algorithm) throws NoSuchAlgorithmException {
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

        // Our purpose here is just to throw an exception immediately if the algorithm is bogus.
        Mac.getInstance(algorithm);
        this.algorithm = algorithm;
    }

    public int getOneTimePassword(final Key key, final long counter) throws InvalidKeyException {
        final Mac mac;

        try {
            mac = Mac.getInstance(this.algorithm);
            mac.init(key);
        } catch (final NoSuchAlgorithmException e) {
            // This should never happen since we verify that the algorithm is legit in the constructor.
            throw new RuntimeException(e);
        }

        final ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.putLong(0, counter);

        final byte[] hmac = mac.doFinal(buffer.array());
        assert hmac.length == 20;

        final int offset = hmac[19] & 0x0f;

        for (int i = 0; i < 4; i++) {
            // Note that we're re-using the first four bytes of the buffer here; we just ignore the latter four from
            // here on out.
            buffer.put(i, hmac[i + offset]);
        }

        final int hotp = buffer.getInt(0) & 0x7fffffff;

        return hotp % this.modDivisor;
    }
}

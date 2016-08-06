package com.eatthepath.otp;

import static org.junit.Assert.*;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.spec.SecretKeySpec;

import org.junit.Test;

public class HmacOneTimePasswordGeneratorTest {

    @Test
    public void testGetOneTimePassword() throws InvalidKeyException, NoSuchAlgorithmException {
        final HmacOneTimePasswordGenerator hmacOneTimePasswordGenerator = new HmacOneTimePasswordGenerator();

        final SecretKeySpec keySpec = new SecretKeySpec("12345678901234567890".getBytes(StandardCharsets.US_ASCII), "RAW");

        final int[] expectedValues = new int[] {
                755224,
                287082,
                359152,
                969429,
                338314,
                254676,
                287922,
                162583,
                399871,
                520489
        };

        for (int i = 0; i < expectedValues.length; i++) {
            assertEquals(expectedValues[i], hmacOneTimePasswordGenerator.getOneTimePassword(keySpec, i));
        }
    }
}

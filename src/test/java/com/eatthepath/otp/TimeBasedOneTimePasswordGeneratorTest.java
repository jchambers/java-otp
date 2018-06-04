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

import junitparams.JUnitParamsRunner;
import junitparams.Parameters;
import org.junit.Test;
import org.junit.runner.RunWith;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertEquals;

@RunWith(JUnitParamsRunner.class)
public class TimeBasedOneTimePasswordGeneratorTest extends HmacOneTimePasswordGeneratorTest {

    @Override
    protected HmacOneTimePasswordGenerator getDefaultGenerator() throws NoSuchAlgorithmException {
        return new TimeBasedOneTimePasswordGenerator();
    }

    @Test
    public void testGetTimeStep() throws NoSuchAlgorithmException {
        final long timeStepSeconds = 97;

        final TimeBasedOneTimePasswordGenerator totp =
                new TimeBasedOneTimePasswordGenerator(timeStepSeconds, TimeUnit.SECONDS);

        assertEquals(timeStepSeconds, totp.getTimeStep(TimeUnit.SECONDS));
        assertEquals(timeStepSeconds * 1000, totp.getTimeStep(TimeUnit.MILLISECONDS));
    }

    /**
     * Tests time-based one-time password generation using the test vectors from
     * <a href="https://tools.ietf.org/html/rfc6238#appendix-B">RFC&nbsp;6238, Appendix B</a>. Note that the RFC
     * incorrectly states that the same key is used for all test vectors. The
     * <a href="https://www.rfc-editor.org/errata_search.php?rfc=6238&eid=2866">errata</a> correctly points out that
     * different keys are used for each of the various HMAC algorithms.
     */
    @Test
    @Parameters({
            "HmacSHA1,   59,          94287082",
            "HmacSHA1,   1111111109,   7081804",
            "HmacSHA1,   1111111111,  14050471",
            "HmacSHA1,   1234567890,  89005924",
            "HmacSHA1,   2000000000,  69279037",
            "HmacSHA1,   20000000000, 65353130",
            "HmacSHA256, 59,          46119246",
            "HmacSHA256, 1111111109,  68084774",
            "HmacSHA256, 1111111111,  67062674",
            "HmacSHA256, 1234567890,  91819424",
            "HmacSHA256, 2000000000,  90698825",
            "HmacSHA256, 20000000000, 77737706",
            "HmacSHA512, 59,          90693936",
            "HmacSHA512, 1111111109,  25091201",
            "HmacSHA512, 1111111111,  99943326",
            "HmacSHA512, 1234567890,  93441116",
            "HmacSHA512, 2000000000,  38618901",
            "HmacSHA512, 20000000000, 47863826" })
    public void testGenerateOneTimePassword(final String algorithm, final long epochSeconds, final int expectedOneTimePassword) throws Exception {

        final TimeBasedOneTimePasswordGenerator totp =
                new TimeBasedOneTimePasswordGenerator(30, TimeUnit.SECONDS, 8, algorithm);

        final Date date = new Date(TimeUnit.SECONDS.toMillis(epochSeconds));

        assertEquals(expectedOneTimePassword, totp.generateOneTimePassword(getKeyForAlgorithm(algorithm), date));
    }

    private static Key getKeyForAlgorithm(final String algorithm) {
        final String keyString;

        switch (algorithm) {
            case "HmacSHA1": {
                keyString = "12345678901234567890";
                break;
            }

            case "HmacSHA256": {
                keyString = "12345678901234567890123456789012";
                break;
            }

            case "HmacSHA512": {
                keyString = "1234567890123456789012345678901234567890123456789012345678901234";
                break;
            }

            default: {
                throw new IllegalArgumentException("Unexpected algorithm: " + algorithm);
            }
        }

        return new SecretKeySpec(keyString.getBytes(StandardCharsets.US_ASCII), "RAW");
    }
}

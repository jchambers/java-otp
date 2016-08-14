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

import static org.junit.Assert.*;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import javax.crypto.spec.SecretKeySpec;

import org.junit.Test;

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
     * Tests time-based one-time password generation using HMAC-SHA1 and the test vectors from
     * <a href="https://tools.ietf.org/html/rfc6238#appendix-B">RFC&nbsp;6238, Appendix B</a>.
     */
    @Test
    public void testGenerateOneTimePasswordSha1() throws NoSuchAlgorithmException, InvalidKeyException {
        final TimeBasedOneTimePasswordGenerator totp =
                new TimeBasedOneTimePasswordGenerator(30, TimeUnit.SECONDS, 8, TimeBasedOneTimePasswordGenerator.TOTP_ALGORITHM_HMAC_SHA1);

        final Key key;
        {
            final String keyString = "12345678901234567890";
            key = new SecretKeySpec(keyString.getBytes(StandardCharsets.US_ASCII), "RAW");
        }

        final Map<Date, Integer> expectedPasswords = new HashMap<>();
        expectedPasswords.put(new Date(TimeUnit.SECONDS.toMillis(59)), 94287082);
        expectedPasswords.put(new Date(TimeUnit.SECONDS.toMillis(1111111109)), 7081804);
        expectedPasswords.put(new Date(TimeUnit.SECONDS.toMillis(1111111111)), 14050471);
        expectedPasswords.put(new Date(TimeUnit.SECONDS.toMillis(1234567890)), 89005924);
        expectedPasswords.put(new Date(TimeUnit.SECONDS.toMillis(2000000000)), 69279037);
        expectedPasswords.put(new Date(TimeUnit.SECONDS.toMillis(20000000000L)), 65353130);

        this.validateOneTimePasswords(totp, key, expectedPasswords);
    }

    /**
     * Tests time-based one-time password generation using HMAC-SHA256 and the test vectors from
     * <a href="https://tools.ietf.org/html/rfc6238#appendix-B">RFC&nbsp;6238, Appendix B</a>.
     */
    @Test
    public void testGenerateOneTimePasswordSha256() throws NoSuchAlgorithmException, InvalidKeyException {
        final TimeBasedOneTimePasswordGenerator totp =
                new TimeBasedOneTimePasswordGenerator(30, TimeUnit.SECONDS, 8, TimeBasedOneTimePasswordGenerator.TOTP_ALGORITHM_HMAC_SHA256);

        final Key key;
        {
            // The RFC incorrectly states that the same key is used for all test vectors, but that's not actually true;
            // see the errata (https://www.rfc-editor.org/errata_search.php?rfc=6238&eid=2866) for details
            final String keyString = "12345678901234567890123456789012";
            key = new SecretKeySpec(keyString.getBytes(StandardCharsets.US_ASCII), "RAW");
        }

        final Map<Date, Integer> expectedPasswords = new HashMap<>();
        expectedPasswords.put(new Date(TimeUnit.SECONDS.toMillis(59)), 46119246);
        expectedPasswords.put(new Date(TimeUnit.SECONDS.toMillis(1111111109)), 68084774);
        expectedPasswords.put(new Date(TimeUnit.SECONDS.toMillis(1111111111)), 67062674);
        expectedPasswords.put(new Date(TimeUnit.SECONDS.toMillis(1234567890)), 91819424);
        expectedPasswords.put(new Date(TimeUnit.SECONDS.toMillis(2000000000)), 90698825);
        expectedPasswords.put(new Date(TimeUnit.SECONDS.toMillis(20000000000L)), 77737706);

        this.validateOneTimePasswords(totp, key, expectedPasswords);
    }

    /**
     * Tests time-based one-time password generation using HMAC-SHA512 and the test vectors from
     * <a href="https://tools.ietf.org/html/rfc6238#appendix-B">RFC&nbsp;6238, Appendix B</a>.
     */
    @Test
    public void testGenerateOneTimePasswordSha512() throws NoSuchAlgorithmException, InvalidKeyException {
        final TimeBasedOneTimePasswordGenerator totp =
                new TimeBasedOneTimePasswordGenerator(30, TimeUnit.SECONDS, 8, TimeBasedOneTimePasswordGenerator.TOTP_ALGORITHM_HMAC_SHA512);

        final Key key;
        {
            // The RFC incorrectly states that the same key is used for all test vectors, but that's not actually true;
            // see the errata (https://www.rfc-editor.org/errata_search.php?rfc=6238&eid=2866) for details
            final String keyString = "1234567890123456789012345678901234567890123456789012345678901234";
            key = new SecretKeySpec(keyString.getBytes(StandardCharsets.US_ASCII), "RAW");
        }

        final Map<Date, Integer> expectedPasswords = new HashMap<>();
        expectedPasswords.put(new Date(TimeUnit.SECONDS.toMillis(59)), 90693936);
        expectedPasswords.put(new Date(TimeUnit.SECONDS.toMillis(1111111109)), 25091201);
        expectedPasswords.put(new Date(TimeUnit.SECONDS.toMillis(1111111111)), 99943326);
        expectedPasswords.put(new Date(TimeUnit.SECONDS.toMillis(1234567890)), 93441116);
        expectedPasswords.put(new Date(TimeUnit.SECONDS.toMillis(2000000000)), 38618901);
        expectedPasswords.put(new Date(TimeUnit.SECONDS.toMillis(20000000000L)), 47863826);

        this.validateOneTimePasswords(totp, key, expectedPasswords);
    }

    private void validateOneTimePasswords(final TimeBasedOneTimePasswordGenerator totp, final Key key, final Map<Date, Integer> expectedPasswords) throws InvalidKeyException {
        for (final Map.Entry<Date, Integer> entry : expectedPasswords.entrySet()) {
            final Date date = entry.getKey();
            final int expectedPassword = entry.getValue();

            assertEquals(expectedPassword, totp.generateOneTimePassword(key, date));
        }
    }
}

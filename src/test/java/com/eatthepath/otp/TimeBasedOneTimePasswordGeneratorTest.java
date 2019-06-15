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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.params.provider.Arguments.arguments;

public class TimeBasedOneTimePasswordGeneratorTest extends HmacOneTimePasswordGeneratorTest {

    private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";
    private static final String HMAC_SHA256_ALGORITHM = "HmacSHA256";
    private static final String HMAC_SHA512_ALGORITHM = "HmacSHA512";

    private static final Key HMAC_SHA1_KEY =
            new SecretKeySpec("12345678901234567890".getBytes(StandardCharsets.US_ASCII), "RAW");

    private static final Key HMAC_SHA256_KEY =
            new SecretKeySpec("12345678901234567890123456789012".getBytes(StandardCharsets.US_ASCII), "RAW");

    private static final Key HMAC_SHA512_KEY =
            new SecretKeySpec("1234567890123456789012345678901234567890123456789012345678901234".getBytes(StandardCharsets.US_ASCII), "RAW");

    @Override
    protected HmacOneTimePasswordGenerator getDefaultGenerator() throws NoSuchAlgorithmException {
        return new TimeBasedOneTimePasswordGenerator();
    }

    @Test
    void testGetTimeStep() throws NoSuchAlgorithmException {
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
    @ParameterizedTest
    @MethodSource("totpTestVectorSource")
    void testGenerateOneTimePassword(final String algorithm, final Key key, final long epochSeconds, final int expectedOneTimePassword) throws Exception {

        final TimeBasedOneTimePasswordGenerator totp =
                new TimeBasedOneTimePasswordGenerator(30, TimeUnit.SECONDS, 8, algorithm);

        final Date date = new Date(TimeUnit.SECONDS.toMillis(epochSeconds));

        assertEquals(expectedOneTimePassword, totp.generateOneTimePassword(key, date));
    }

    static Stream<Arguments> totpTestVectorSource() {
        return Stream.of(
                arguments(HMAC_SHA1_ALGORITHM,   HMAC_SHA1_KEY,            59L, 94287082),
                arguments(HMAC_SHA1_ALGORITHM,   HMAC_SHA1_KEY,    1111111109L,  7081804),
                arguments(HMAC_SHA1_ALGORITHM,   HMAC_SHA1_KEY,    1111111111L, 14050471),
                arguments(HMAC_SHA1_ALGORITHM,   HMAC_SHA1_KEY,    1234567890L, 89005924),
                arguments(HMAC_SHA1_ALGORITHM,   HMAC_SHA1_KEY,    2000000000L, 69279037),
                arguments(HMAC_SHA1_ALGORITHM,   HMAC_SHA1_KEY,   20000000000L, 65353130),
                arguments(HMAC_SHA256_ALGORITHM, HMAC_SHA256_KEY,          59L, 46119246),
                arguments(HMAC_SHA256_ALGORITHM, HMAC_SHA256_KEY,  1111111109L, 68084774),
                arguments(HMAC_SHA256_ALGORITHM, HMAC_SHA256_KEY,  1111111111L, 67062674),
                arguments(HMAC_SHA256_ALGORITHM, HMAC_SHA256_KEY,  1234567890L, 91819424),
                arguments(HMAC_SHA256_ALGORITHM, HMAC_SHA256_KEY,  2000000000L, 90698825),
                arguments(HMAC_SHA256_ALGORITHM, HMAC_SHA256_KEY, 20000000000L, 77737706),
                arguments(HMAC_SHA512_ALGORITHM, HMAC_SHA512_KEY,          59L, 90693936),
                arguments(HMAC_SHA512_ALGORITHM, HMAC_SHA512_KEY,  1111111109L, 25091201),
                arguments(HMAC_SHA512_ALGORITHM, HMAC_SHA512_KEY,  1111111111L, 99943326),
                arguments(HMAC_SHA512_ALGORITHM, HMAC_SHA512_KEY,  1234567890L, 93441116),
                arguments(HMAC_SHA512_ALGORITHM, HMAC_SHA512_KEY,  2000000000L, 38618901),
                arguments(HMAC_SHA512_ALGORITHM, HMAC_SHA512_KEY, 20000000000L, 47863826)
        );
    }
}

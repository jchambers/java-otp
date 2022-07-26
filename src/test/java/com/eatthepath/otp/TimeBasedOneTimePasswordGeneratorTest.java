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

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.junit.jupiter.params.provider.Arguments.arguments;

public class TimeBasedOneTimePasswordGeneratorTest {

    private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";
    private static final String HMAC_SHA256_ALGORITHM = "HmacSHA256";
    private static final String HMAC_SHA512_ALGORITHM = "HmacSHA512";

    private static final byte[] HMAC_SHA1_KEY_BYTES =
            "12345678901234567890".getBytes(StandardCharsets.US_ASCII);

    private static final byte[] HMAC_SHA256_KEY_BYTES =
            "12345678901234567890123456789012".getBytes(StandardCharsets.US_ASCII);

    private static final byte[] HMAC_SHA512_KEY_BYTES =
            "1234567890123456789012345678901234567890123456789012345678901234".getBytes(StandardCharsets.US_ASCII);

    @Test
    void testGetPasswordLength() {
        final int passwordLength = 7;
        assertEquals(passwordLength, new TimeBasedOneTimePasswordGenerator(Duration.ofSeconds(30), passwordLength).getPasswordLength());
    }

    @Test
    void testGetAlgorithm() {
        final String algorithm = TimeBasedOneTimePasswordGenerator.TOTP_ALGORITHM_HMAC_SHA256;
        assertEquals(algorithm, new TimeBasedOneTimePasswordGenerator(Duration.ofSeconds(30), 6, algorithm).getAlgorithm());
    }

    @Test
    void testGetTimeStep() {
        final Duration timeStep = Duration.ofSeconds(97);
        assertEquals(timeStep, new TimeBasedOneTimePasswordGenerator(timeStep).getTimeStep());
    }

    /**
     * Tests time-based one-time password generation using the test vectors from
     * <a href="https://tools.ietf.org/html/rfc6238#appendix-B">RFC&nbsp;6238, Appendix B</a>. Note that the RFC
     * incorrectly states that the same key is used for all test vectors. The
     * <a href="https://www.rfc-editor.org/errata_search.php?rfc=6238&eid=2866">errata</a> correctly points out that
     * different keys are used for each of the various HMAC algorithms.
     */
    @ParameterizedTest
    @MethodSource("argumentsForTestGenerateOneTimePasswordTotp")
    void testGenerateOneTimePasswordTotp(final String algorithm, final byte[] keyBytes, final long epochSeconds, final int expectedOneTimePassword) throws Exception {
        assumeAlgorithmSupported(algorithm);

        final TimeBasedOneTimePasswordGenerator totp =
                new TimeBasedOneTimePasswordGenerator(Duration.ofSeconds(30), 8, algorithm);

        final Instant timestamp = Instant.ofEpochSecond(epochSeconds);
        final Key key = new SecretKeySpec(keyBytes, algorithm);

        assertEquals(expectedOneTimePassword, totp.generateOneTimePassword(key, timestamp));
    }

    private static Stream<Arguments> argumentsForTestGenerateOneTimePasswordTotp() {
        return Stream.of(
                arguments(HMAC_SHA1_ALGORITHM,   HMAC_SHA1_KEY_BYTES,            59L, 94287082),
                arguments(HMAC_SHA1_ALGORITHM,   HMAC_SHA1_KEY_BYTES,    1111111109L,  7081804),
                arguments(HMAC_SHA1_ALGORITHM,   HMAC_SHA1_KEY_BYTES,    1111111111L, 14050471),
                arguments(HMAC_SHA1_ALGORITHM,   HMAC_SHA1_KEY_BYTES,    1234567890L, 89005924),
                arguments(HMAC_SHA1_ALGORITHM,   HMAC_SHA1_KEY_BYTES,    2000000000L, 69279037),
                arguments(HMAC_SHA1_ALGORITHM,   HMAC_SHA1_KEY_BYTES,   20000000000L, 65353130),
                arguments(HMAC_SHA256_ALGORITHM, HMAC_SHA256_KEY_BYTES,          59L, 46119246),
                arguments(HMAC_SHA256_ALGORITHM, HMAC_SHA256_KEY_BYTES,  1111111109L, 68084774),
                arguments(HMAC_SHA256_ALGORITHM, HMAC_SHA256_KEY_BYTES,  1111111111L, 67062674),
                arguments(HMAC_SHA256_ALGORITHM, HMAC_SHA256_KEY_BYTES,  1234567890L, 91819424),
                arguments(HMAC_SHA256_ALGORITHM, HMAC_SHA256_KEY_BYTES,  2000000000L, 90698825),
                arguments(HMAC_SHA256_ALGORITHM, HMAC_SHA256_KEY_BYTES, 20000000000L, 77737706),
                arguments(HMAC_SHA512_ALGORITHM, HMAC_SHA512_KEY_BYTES,          59L, 90693936),
                arguments(HMAC_SHA512_ALGORITHM, HMAC_SHA512_KEY_BYTES,  1111111109L, 25091201),
                arguments(HMAC_SHA512_ALGORITHM, HMAC_SHA512_KEY_BYTES,  1111111111L, 99943326),
                arguments(HMAC_SHA512_ALGORITHM, HMAC_SHA512_KEY_BYTES,  1234567890L, 93441116),
                arguments(HMAC_SHA512_ALGORITHM, HMAC_SHA512_KEY_BYTES,  2000000000L, 38618901),
                arguments(HMAC_SHA512_ALGORITHM, HMAC_SHA512_KEY_BYTES, 20000000000L, 47863826)
        );
    }

    @ParameterizedTest
    @MethodSource("argumentsForTestGenerateOneTimePasswordStringTotp")
    void testGenerateOneTimePasswordStringTotp(final String algorithm, final byte[] keyBytes, final long epochSeconds, final String expectedOneTimePassword) throws Exception {
        assumeAlgorithmSupported(algorithm);

        final TimeBasedOneTimePasswordGenerator totp =
                new TimeBasedOneTimePasswordGenerator(Duration.ofSeconds(30), 8, algorithm);

        final Instant timestamp = Instant.ofEpochSecond(epochSeconds);
        final Key key = new SecretKeySpec(keyBytes, algorithm);

        assertEquals(expectedOneTimePassword, totp.generateOneTimePasswordString(key, timestamp));
    }

    private static Stream<Arguments> argumentsForTestGenerateOneTimePasswordStringTotp() {
        return Stream.of(
                arguments(HMAC_SHA1_ALGORITHM,   HMAC_SHA1_KEY_BYTES,            59L, "94287082"),
                arguments(HMAC_SHA1_ALGORITHM,   HMAC_SHA1_KEY_BYTES,    1111111109L, "07081804"),
                arguments(HMAC_SHA1_ALGORITHM,   HMAC_SHA1_KEY_BYTES,    1111111111L, "14050471"),
                arguments(HMAC_SHA1_ALGORITHM,   HMAC_SHA1_KEY_BYTES,    1234567890L, "89005924"),
                arguments(HMAC_SHA1_ALGORITHM,   HMAC_SHA1_KEY_BYTES,    2000000000L, "69279037"),
                arguments(HMAC_SHA1_ALGORITHM,   HMAC_SHA1_KEY_BYTES,   20000000000L, "65353130"),
                arguments(HMAC_SHA256_ALGORITHM, HMAC_SHA256_KEY_BYTES,          59L, "46119246"),
                arguments(HMAC_SHA256_ALGORITHM, HMAC_SHA256_KEY_BYTES,  1111111109L, "68084774"),
                arguments(HMAC_SHA256_ALGORITHM, HMAC_SHA256_KEY_BYTES,  1111111111L, "67062674"),
                arguments(HMAC_SHA256_ALGORITHM, HMAC_SHA256_KEY_BYTES,  1234567890L, "91819424"),
                arguments(HMAC_SHA256_ALGORITHM, HMAC_SHA256_KEY_BYTES,  2000000000L, "90698825"),
                arguments(HMAC_SHA256_ALGORITHM, HMAC_SHA256_KEY_BYTES, 20000000000L, "77737706"),
                arguments(HMAC_SHA512_ALGORITHM, HMAC_SHA512_KEY_BYTES,          59L, "90693936"),
                arguments(HMAC_SHA512_ALGORITHM, HMAC_SHA512_KEY_BYTES,  1111111109L, "25091201"),
                arguments(HMAC_SHA512_ALGORITHM, HMAC_SHA512_KEY_BYTES,  1111111111L, "99943326"),
                arguments(HMAC_SHA512_ALGORITHM, HMAC_SHA512_KEY_BYTES,  1234567890L, "93441116"),
                arguments(HMAC_SHA512_ALGORITHM, HMAC_SHA512_KEY_BYTES,  2000000000L, "38618901"),
                arguments(HMAC_SHA512_ALGORITHM, HMAC_SHA512_KEY_BYTES, 20000000000L, "47863826")
        );
    }

    @ParameterizedTest
    @MethodSource("argumentsForTestGenerateOneTimePasswordStringLocaleTotp")
    void testGenerateOneTimePasswordStringLocaleTotp(final String algorithm, final byte[] keyBytes, final long epochSeconds, final Locale locale, final String expectedOneTimePassword) throws Exception {
        assumeAlgorithmSupported(algorithm);

        final TimeBasedOneTimePasswordGenerator totp =
                new TimeBasedOneTimePasswordGenerator(Duration.ofSeconds(30), 8, algorithm);

        final Instant timestamp = Instant.ofEpochSecond(epochSeconds);
        final Key key = new SecretKeySpec(keyBytes, algorithm);

        assertEquals(expectedOneTimePassword, totp.generateOneTimePasswordString(key, timestamp, locale));
    }

    private static Stream<Arguments> argumentsForTestGenerateOneTimePasswordStringLocaleTotp() {
        final Locale locale = Locale.forLanguageTag("hi-IN-u-nu-Deva");

        return Stream.of(
                arguments(HMAC_SHA1_ALGORITHM,   HMAC_SHA1_KEY_BYTES,            59L, locale, "९४२८७०८२"),
                arguments(HMAC_SHA1_ALGORITHM,   HMAC_SHA1_KEY_BYTES,    1111111109L, locale, "०७०८१८०४"),
                arguments(HMAC_SHA1_ALGORITHM,   HMAC_SHA1_KEY_BYTES,    1111111111L, locale, "१४०५०४७१"),
                arguments(HMAC_SHA1_ALGORITHM,   HMAC_SHA1_KEY_BYTES,    1234567890L, locale, "८९००५९२४"),
                arguments(HMAC_SHA1_ALGORITHM,   HMAC_SHA1_KEY_BYTES,    2000000000L, locale, "६९२७९०३७"),
                arguments(HMAC_SHA1_ALGORITHM,   HMAC_SHA1_KEY_BYTES,   20000000000L, locale, "६५३५३१३०"),
                arguments(HMAC_SHA256_ALGORITHM, HMAC_SHA256_KEY_BYTES,          59L, locale, "४६११९२४६"),
                arguments(HMAC_SHA256_ALGORITHM, HMAC_SHA256_KEY_BYTES,  1111111109L, locale, "६८०८४७७४"),
                arguments(HMAC_SHA256_ALGORITHM, HMAC_SHA256_KEY_BYTES,  1111111111L, locale, "६७०६२६७४"),
                arguments(HMAC_SHA256_ALGORITHM, HMAC_SHA256_KEY_BYTES,  1234567890L, locale, "९१८१९४२४"),
                arguments(HMAC_SHA256_ALGORITHM, HMAC_SHA256_KEY_BYTES,  2000000000L, locale, "९०६९८८२५"),
                arguments(HMAC_SHA256_ALGORITHM, HMAC_SHA256_KEY_BYTES, 20000000000L, locale, "७७७३७७०६"),
                arguments(HMAC_SHA512_ALGORITHM, HMAC_SHA512_KEY_BYTES,          59L, locale, "९०६९३९३६"),
                arguments(HMAC_SHA512_ALGORITHM, HMAC_SHA512_KEY_BYTES,  1111111109L, locale, "२५०९१२०१"),
                arguments(HMAC_SHA512_ALGORITHM, HMAC_SHA512_KEY_BYTES,  1111111111L, locale, "९९९४३३२६"),
                arguments(HMAC_SHA512_ALGORITHM, HMAC_SHA512_KEY_BYTES,  1234567890L, locale, "९३४४१११६"),
                arguments(HMAC_SHA512_ALGORITHM, HMAC_SHA512_KEY_BYTES,  2000000000L, locale, "३८६१८९०१"),
                arguments(HMAC_SHA512_ALGORITHM, HMAC_SHA512_KEY_BYTES, 20000000000L, locale, "४७८६३८२६")
        );
    }

    private static void assumeAlgorithmSupported(final String algorithm) {
        boolean algorithmSupported = true;

        try {
            Mac.getInstance(algorithm);
        } catch (final NoSuchAlgorithmException e) {
            algorithmSupported = false;
        }

        assumeTrue(algorithmSupported, "Algorithm not supported: " + algorithm);
    }
}

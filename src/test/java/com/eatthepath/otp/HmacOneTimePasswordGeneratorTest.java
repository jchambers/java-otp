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
import java.util.Locale;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.params.provider.Arguments.arguments;

public class HmacOneTimePasswordGeneratorTest {

    private static final Key HOTP_KEY =
            new SecretKeySpec("12345678901234567890".getBytes(StandardCharsets.US_ASCII),
                    HmacOneTimePasswordGenerator.HOTP_HMAC_ALGORITHM);

    @Test
    void testHmacOneTimePasswordGeneratorWithShortPasswordLength() {
        assertThrows(IllegalArgumentException.class, () -> new HmacOneTimePasswordGenerator(5));
    }

    @Test
    void testHmacOneTimePasswordGeneratorWithLongPasswordLength() {
        assertThrows(IllegalArgumentException.class, () -> new HmacOneTimePasswordGenerator(9));
    }

    @Test
    void testHmacOneTimePasswordGeneratorWithBogusAlgorithm() {
        final UncheckedNoSuchAlgorithmException exception = assertThrows(UncheckedNoSuchAlgorithmException.class, () ->
                new HmacOneTimePasswordGenerator(6, "Definitely not a real algorithm"));

        assertNotNull(exception.getCause());
    }

    @Test
    void testGetPasswordLength() {
        final int passwordLength = 7;
        assertEquals(passwordLength, new HmacOneTimePasswordGenerator(passwordLength).getPasswordLength());
    }

    @Test
    void testGetAlgorithm() {
        final String algorithm = "HmacSHA256";
        assertEquals(algorithm, new HmacOneTimePasswordGenerator(6, algorithm).getAlgorithm());
    }

    /**
     * Tests generation of one-time passwords using the test vectors from
     * <a href="https://tools.ietf.org/html/rfc4226#appendix-D">RFC&nbsp;4226, Appendix D</a>.
     */
    @ParameterizedTest
    @MethodSource("argumentsForTestGenerateOneTimePasswordHotp")
    void testGenerateOneTimePassword(final int counter, final int expectedOneTimePassword) throws Exception {
        assertEquals(expectedOneTimePassword, new HmacOneTimePasswordGenerator().generateOneTimePassword(HOTP_KEY, counter));
    }

    @Test
    void testGenerateOneTimePasswordRepeated() throws Exception {
        final HmacOneTimePasswordGenerator hotpGenerator = new HmacOneTimePasswordGenerator();

        assertEquals(755224, hotpGenerator.generateOneTimePassword(HOTP_KEY, 0));
        assertEquals(287082, hotpGenerator.generateOneTimePassword(HOTP_KEY, 1));
    }

    private static Stream<Arguments> argumentsForTestGenerateOneTimePasswordHotp() {
        return Stream.of(
                arguments(0, 755224),
                arguments(1, 287082),
                arguments(2, 359152),
                arguments(3, 969429),
                arguments(4, 338314),
                arguments(5, 254676),
                arguments(6, 287922),
                arguments(7, 162583),
                arguments(8, 399871),
                arguments(9, 520489)
        );
    }

    @ParameterizedTest
    @MethodSource("argumentsForTestGenerateOneTimePasswordStringHotp")
    void testGenerateOneTimePasswordString(final int counter, final String expectedOneTimePassword) throws Exception {
        Locale.setDefault(Locale.US);
        assertEquals(expectedOneTimePassword, new HmacOneTimePasswordGenerator().generateOneTimePasswordString(HOTP_KEY, counter));
    }

    private static Stream<Arguments> argumentsForTestGenerateOneTimePasswordStringHotp() {
        return Stream.of(
                arguments(0, "755224"),
                arguments(1, "287082"),
                arguments(2, "359152"),
                arguments(3, "969429"),
                arguments(4, "338314"),
                arguments(5, "254676"),
                arguments(6, "287922"),
                arguments(7, "162583"),
                arguments(8, "399871"),
                arguments(9, "520489")
        );
    }

    @ParameterizedTest
    @MethodSource("argumentsForTestGenerateOneTimePasswordStringLocaleHotp")
    void testGenerateOneTimePasswordStringLocale(final int counter, final Locale locale, final String expectedOneTimePassword) throws Exception {
        Locale.setDefault(Locale.US);
        assertEquals(expectedOneTimePassword, new HmacOneTimePasswordGenerator().generateOneTimePasswordString(HOTP_KEY, counter, locale));
    }

    private static Stream<Arguments> argumentsForTestGenerateOneTimePasswordStringLocaleHotp() {
        final Locale locale = Locale.forLanguageTag("hi-IN-u-nu-Deva");

        return Stream.of(
                arguments(0, locale, "७५५२२४"),
                arguments(1, locale, "२८७०८२"),
                arguments(2, locale, "३५९१५२"),
                arguments(3, locale, "९६९४२९"),
                arguments(4, locale, "३३८३१४"),
                arguments(5, locale, "२५४६७६"),
                arguments(6, locale, "२८७९२२"),
                arguments(7, locale, "१६२५८३"),
                arguments(8, locale, "३९९८७१"),
                arguments(9, locale, "५२०४८९")
        );
    }
}

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
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Locale;
import java.util.concurrent.*;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class HmacOneTimePasswordGeneratorTest {

    private static final Key HOTP_KEY =
            new SecretKeySpec("12345678901234567890".getBytes(StandardCharsets.US_ASCII),
                    HmacOneTimePasswordGenerator.HOTP_HMAC_ALGORITHM);

    private static final int[] TEST_VECTORS = new int[] {
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

    @Test
    void hmacOneTimePasswordGeneratorWithShortPasswordLength() {
        assertThrows(IllegalArgumentException.class, () -> new HmacOneTimePasswordGenerator(5));
    }

    @Test
    void hmacOneTimePasswordGeneratorWithLongPasswordLength() {
        assertThrows(IllegalArgumentException.class, () -> new HmacOneTimePasswordGenerator(9));
    }

    @Test
    void hmacOneTimePasswordGeneratorWithBogusAlgorithm() {
        assertThrows(NoSuchAlgorithmException.class, () ->
            new HmacOneTimePasswordGenerator(6, "Definitely not a real algorithm"));
    }

    @Test
    void getPasswordLength() {
        final int passwordLength = 7;
        assertEquals(passwordLength, new HmacOneTimePasswordGenerator(passwordLength).getPasswordLength());
    }

    @Test
    void getAlgorithm() throws NoSuchAlgorithmException {
        final String algorithm = "HmacSHA256";
        assertEquals(algorithm, new HmacOneTimePasswordGenerator(6, algorithm).getAlgorithm());
    }

    /**
     * Tests generation of one-time passwords using the test vectors from
     * <a href="https://tools.ietf.org/html/rfc4226#appendix-D">RFC&nbsp;4226, Appendix D</a>.
     */
    @ParameterizedTest
    @MethodSource
    void generateOneTimePassword(final int counter, final int expectedOneTimePassword) throws Exception {
        assertEquals(expectedOneTimePassword, new HmacOneTimePasswordGenerator().generateOneTimePassword(HOTP_KEY, counter));
    }

    private static Stream<Arguments> generateOneTimePassword() {
        return IntStream.range(0, TEST_VECTORS.length)
            .mapToObj(counter -> Arguments.of(counter, TEST_VECTORS[counter]));
    }

    @Test
    void generateOneTimePasswordRepeated() throws Exception {
        final HmacOneTimePasswordGenerator hotpGenerator = new HmacOneTimePasswordGenerator();

        for (int counter = 0; counter < TEST_VECTORS.length; counter++) {
            assertEquals(TEST_VECTORS[counter], hotpGenerator.generateOneTimePassword(HOTP_KEY, counter));
        }
    }

    @ParameterizedTest
    @MethodSource
    void generateOneTimePasswordString(final int counter, final String expectedOneTimePassword) throws Exception {
        Locale.setDefault(Locale.US);
        assertEquals(expectedOneTimePassword, new HmacOneTimePasswordGenerator().generateOneTimePasswordString(HOTP_KEY, counter));
    }

    private static Stream<Arguments> generateOneTimePasswordString() {
        return IntStream.range(0, TEST_VECTORS.length)
            .mapToObj(counter -> Arguments.of(counter, String.valueOf(TEST_VECTORS[counter])));
    }

    @ParameterizedTest
    @MethodSource
    void generateOneTimePasswordStringLocale(final int counter, final Locale locale, final String expectedOneTimePassword) throws Exception {
        Locale.setDefault(Locale.US);
        assertEquals(expectedOneTimePassword, new HmacOneTimePasswordGenerator().generateOneTimePasswordString(HOTP_KEY, counter, locale));
    }

    private static Stream<Arguments> generateOneTimePasswordStringLocale() {
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

    @Test
    void validateOneTimePasswordInt() throws InvalidKeyException {
        final HmacOneTimePasswordGenerator hotp = new HmacOneTimePasswordGenerator();
        final long counter = ThreadLocalRandom.current().nextLong();

        assertTrue(hotp.validateOneTimePassword(HOTP_KEY, counter, hotp.generateOneTimePassword(HOTP_KEY, counter)));
        assertFalse(hotp.validateOneTimePassword(HOTP_KEY, counter, hotp.generateOneTimePassword(HOTP_KEY, counter + 1)));
    }

    @Test
    void validateOneTimePasswordString() throws InvalidKeyException {
        final HmacOneTimePasswordGenerator hotp = new HmacOneTimePasswordGenerator();

        // A counter value of 36 with HOTP produces a one-time password of "003784" (or "००३७८४" in the hi-IN-u-nu-Deva
        // locale). The leading zeros are an important edge case for string-based tests.
        final long counter = 36;

        assertTrue(hotp.validateOneTimePassword(HOTP_KEY, counter, "003784"));
        assertFalse(hotp.validateOneTimePassword(HOTP_KEY, counter, "3784"));
        assertFalse(hotp.validateOneTimePassword(HOTP_KEY, counter, "0003784"));
        assertFalse(hotp.validateOneTimePassword(HOTP_KEY, counter, "0037840"));

        assertTrue(hotp.validateOneTimePassword(HOTP_KEY, counter, "००३७८४"));
        assertFalse(hotp.validateOneTimePassword(HOTP_KEY, counter, "३७८४"));
        assertFalse(hotp.validateOneTimePassword(HOTP_KEY, counter, "०००३७८४"));
        assertFalse(hotp.validateOneTimePassword(HOTP_KEY, counter, "००३७८४०"));

        assertFalse(hotp.validateOneTimePassword(HOTP_KEY, counter, "cursed"));

        assertThrows(NullPointerException.class, () ->
            hotp.validateOneTimePassword(HOTP_KEY, counter, null));
    }

    @Test
    void generateOneTimePasswordConcurrent() throws InterruptedException {
        final int iterations = 10_000;
        final int threadCount = Runtime.getRuntime().availableProcessors() * 4;
        final CyclicBarrier cyclicBarrier = new CyclicBarrier(threadCount);
        final ExecutorService executorService = Executors.newFixedThreadPool(threadCount);
        @SuppressWarnings("unchecked") final CompletableFuture<Boolean>[] futures = new CompletableFuture[threadCount];

        final HmacOneTimePasswordGenerator hotpGenerator = new HmacOneTimePasswordGenerator();

        for (int thread = 0; thread < threadCount; thread++) {
            futures[thread] = CompletableFuture.supplyAsync(() -> {
                boolean allMatched = true;

                try {
                    cyclicBarrier.await();
                } catch (final InterruptedException | BrokenBarrierException e) {
                    throw new RuntimeException(e);
                }

                for (int i = 0; i < iterations; i++) {
                    final int counter = ThreadLocalRandom.current().nextInt(TEST_VECTORS.length);

                    try {
                        if (hotpGenerator.generateOneTimePassword(HOTP_KEY, counter) != TEST_VECTORS[counter]) {
                            allMatched = false;
                        }
                    } catch (final InvalidKeyException e) {
                        throw new RuntimeException(e);
                    }
                }

                return allMatched;
            }, executorService);
        }

        CompletableFuture.allOf(futures).join();

        assertTrue(Arrays.stream(futures).allMatch(CompletableFuture::join));

        executorService.shutdown();
        assertTrue(executorService.awaitTermination(1, TimeUnit.SECONDS));
    }
}

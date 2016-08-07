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

public class TimeBasedOneTimePasswordGeneratorTest {

    @Test
    public void testGenerateOneTimePasswordSha1() throws NoSuchAlgorithmException, InvalidKeyException {
        final TimeBasedOneTimePasswordGenerator totp =
                new TimeBasedOneTimePasswordGenerator(30, TimeUnit.SECONDS, 8, HmacOneTimePasswordGenerator.ALGORITHM_HMAC_SHA1);

        final Key key = this.generateKey(20);

        final Map<Date, Integer> expectedPasswords = new HashMap<>();
        expectedPasswords.put(new Date(TimeUnit.SECONDS.toMillis(59)), 94287082);
        expectedPasswords.put(new Date(TimeUnit.SECONDS.toMillis(1111111109)), 7081804);
        expectedPasswords.put(new Date(TimeUnit.SECONDS.toMillis(1111111111)), 14050471);
        expectedPasswords.put(new Date(TimeUnit.SECONDS.toMillis(1234567890)), 89005924);
        expectedPasswords.put(new Date(TimeUnit.SECONDS.toMillis(2000000000)), 69279037);
        expectedPasswords.put(new Date(TimeUnit.SECONDS.toMillis(20000000000L)), 65353130);

        this.validateOneTimePasswords(totp, key, expectedPasswords);
    }

    @Test
    public void testGenerateOneTimePasswordSha256() throws NoSuchAlgorithmException, InvalidKeyException {
        final TimeBasedOneTimePasswordGenerator totp =
                new TimeBasedOneTimePasswordGenerator(30, TimeUnit.SECONDS, 8, HmacOneTimePasswordGenerator.ALGORITHM_HMAC_SHA256);

        final Key key = this.generateKey(32);

        final Map<Date, Integer> expectedPasswords = new HashMap<>();
        expectedPasswords.put(new Date(TimeUnit.SECONDS.toMillis(59)), 46119246);
        expectedPasswords.put(new Date(TimeUnit.SECONDS.toMillis(1111111109)), 68084774);
        expectedPasswords.put(new Date(TimeUnit.SECONDS.toMillis(1111111111)), 67062674);
        expectedPasswords.put(new Date(TimeUnit.SECONDS.toMillis(1234567890)), 91819424);
        expectedPasswords.put(new Date(TimeUnit.SECONDS.toMillis(2000000000)), 90698825);
        expectedPasswords.put(new Date(TimeUnit.SECONDS.toMillis(20000000000L)), 77737706);

        this.validateOneTimePasswords(totp, key, expectedPasswords);
    }

    @Test
    public void testGenerateOneTimePasswordSha512() throws NoSuchAlgorithmException, InvalidKeyException {
        final TimeBasedOneTimePasswordGenerator totp =
                new TimeBasedOneTimePasswordGenerator(30, TimeUnit.SECONDS, 8, HmacOneTimePasswordGenerator.ALGORITHM_HMAC_SHA512);

        final Key key = this.generateKey(64);

        final Map<Date, Integer> expectedPasswords = new HashMap<>();
        expectedPasswords.put(new Date(TimeUnit.SECONDS.toMillis(59)), 90693936);
        expectedPasswords.put(new Date(TimeUnit.SECONDS.toMillis(1111111109)), 25091201);
        expectedPasswords.put(new Date(TimeUnit.SECONDS.toMillis(1111111111)), 99943326);
        expectedPasswords.put(new Date(TimeUnit.SECONDS.toMillis(1234567890)), 93441116);
        expectedPasswords.put(new Date(TimeUnit.SECONDS.toMillis(2000000000)), 38618901);
        expectedPasswords.put(new Date(TimeUnit.SECONDS.toMillis(20000000000L)), 47863826);

        this.validateOneTimePasswords(totp, key, expectedPasswords);
    }

    /**
     * <p>Generates a key of a specific length using a string of incrementing decimal digits. It's not at all obvious
     * from <a href="https://tools.ietf.org/html/rfc6238#appendix-B">RFC 6238, Appendix B</a> (in fact, it says the
     * opposite), but each algorithm needs to be tested with its own key. See the
     * <a href="https://www.rfc-editor.org/errata_search.php?rfc=6238&eid=2866">RFC errata</a> for additional
     * details.</p>
     *
     * @param length the length (in bytes) of the key to generate
     *
     * @return a {@code Key} derived from a string of incrementing decimal digits
     */
    private Key generateKey(final int length) {
        final StringBuilder builder = new StringBuilder(length);

        for (int i = 0; i < length; i++) {
            builder.append((i + 1) % 10);
        }

        return new SecretKeySpec(builder.toString().getBytes(StandardCharsets.US_ASCII), "RAW");
    }

    private void validateOneTimePasswords(final TimeBasedOneTimePasswordGenerator totp, final Key key, final Map<Date, Integer> expectedPasswords) throws InvalidKeyException {
        for (final Map.Entry<Date, Integer> entry : expectedPasswords.entrySet()) {
            final Date date = entry.getKey();
            final int expectedPassword = entry.getValue();

            assertEquals(expectedPassword, totp.generateOneTimePassword(key, date));
        }
    }
}

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

import javax.crypto.spec.SecretKeySpec;

import org.junit.Test;

public class HmacOneTimePasswordGeneratorTest {

    @Test(expected = IllegalArgumentException.class)
    public void testHmacOneTimePasswordGeneratorWithShortPasswordLength() throws NoSuchAlgorithmException {
        new HmacOneTimePasswordGenerator(5);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testHmacOneTimePasswordGeneratorWithLongPasswordLength() throws NoSuchAlgorithmException {
        new HmacOneTimePasswordGenerator(9);
    }

    @Test(expected = NoSuchAlgorithmException.class)
    public void testHmacOneTimePasswordGeneratorWithBogusAlgorithm() throws NoSuchAlgorithmException {
        new HmacOneTimePasswordGenerator(6, "Definitely not a real algorithm");
    }

    @Test
    public void testGetPasswordLength() throws NoSuchAlgorithmException {
        final int passwordLength = 7;
        assertEquals(passwordLength, new HmacOneTimePasswordGenerator(passwordLength).getPasswordLength());
    }

    @Test
    public void testGetAlgorithm() throws NoSuchAlgorithmException {
        final String algorithm = "HmacSHA256";
        assertEquals(algorithm, new HmacOneTimePasswordGenerator(6, algorithm).getAlgorithm());
    }

    /**
     * Tests generation of one-time passwords using the test vectors from
     * <a href="https://tools.ietf.org/html/rfc4226#appendix-D">RFC&nbsp;4226, Appendix D</a>.
     */
    @Test
    public void testGetOneTimePassword() throws InvalidKeyException, NoSuchAlgorithmException {
        final HmacOneTimePasswordGenerator hmacOneTimePasswordGenerator = this.getDefaultGenerator();

        final Key key = new SecretKeySpec("12345678901234567890".getBytes(StandardCharsets.US_ASCII), "RAW");

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
            assertEquals(expectedValues[i], hmacOneTimePasswordGenerator.generateOneTimePassword(key, i));
        }
    }

    protected HmacOneTimePasswordGenerator getDefaultGenerator() throws NoSuchAlgorithmException {
        return new HmacOneTimePasswordGenerator();
    }
}

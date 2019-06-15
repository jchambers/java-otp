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

import javax.crypto.KeyGenerator;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;

public class ExampleApp {
    public static void main(final String[] args) throws NoSuchAlgorithmException, InvalidKeyException {
        final TimeBasedOneTimePasswordGenerator totp = new TimeBasedOneTimePasswordGenerator();

        final Key key;
        {
            final KeyGenerator keyGenerator = KeyGenerator.getInstance(totp.getAlgorithm());

            // SHA-1 and SHA-256 prefer 64-byte (512-bit) keys; SHA512 prefers 128-byte (1024-bit) keys
            keyGenerator.init(512);

            key = keyGenerator.generateKey();
        }

        final Instant now = Instant.now();
        final Instant later = now.plus(totp.getTimeStep());

        System.out.format("Current password: %06d\n", totp.generateOneTimePassword(key, now));
        System.out.format("Future password:  %06d\n", totp.generateOneTimePassword(key, later));
    }
}

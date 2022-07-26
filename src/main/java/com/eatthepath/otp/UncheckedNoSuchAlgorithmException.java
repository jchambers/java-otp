package com.eatthepath.otp;

import java.security.NoSuchAlgorithmException;

/**
 * Wraps a {@link NoSuchAlgorithmException} with an unchecked exception.
 *
 * @author <a href="https://github.com/jchambers">Jon Chambers</a>
 */
public class UncheckedNoSuchAlgorithmException extends RuntimeException {

    /**
     * Constructs a new unchecked {@code NoSuchAlgorithmException} instance.
     *
     * @param cause the underlying {@code NoSuchAlgorithmException}
     */
    UncheckedNoSuchAlgorithmException(final NoSuchAlgorithmException cause) {
        super(cause);
    }

    /**
     * Returns the underlying {@link NoSuchAlgorithmException} that caused this exception.
     *
     * @return the underlying {@link NoSuchAlgorithmException} that caused this exception
     */
    @Override
    public NoSuchAlgorithmException getCause() {
        return (NoSuchAlgorithmException) super.getCause();
    }
}

package com.eatthepath.otp;

import java.security.NoSuchAlgorithmException;

/**
 * A runtime exception that indicates that a requested MAC algorithm is not supported by the JVM.
 *
 * @author <a href="https://github.com/jchambers">Jon Chambers</a>
 */
public class NoSuchAlgorithmRuntimeException extends RuntimeException {

    NoSuchAlgorithmRuntimeException(final NoSuchAlgorithmException e) {
        super(e);
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

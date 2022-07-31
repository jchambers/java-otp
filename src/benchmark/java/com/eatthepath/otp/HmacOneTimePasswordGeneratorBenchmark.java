package com.eatthepath.otp;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

import javax.crypto.KeyGenerator;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

@State(Scope.Benchmark)
public class HmacOneTimePasswordGeneratorBenchmark {

    private HmacOneTimePasswordGenerator hotp;
    private Key key;

    private int counter = 0;

    @Setup
    public void setUp() throws NoSuchAlgorithmException {
        this.hotp = new HmacOneTimePasswordGenerator();

        final KeyGenerator keyGenerator = KeyGenerator.getInstance(this.hotp.getAlgorithm());
        keyGenerator.init(512);

        this.key = keyGenerator.generateKey();
    }

    @Benchmark
    public int benchmarkGenerateOneTimePassword() throws InvalidKeyException {
        return this.hotp.generateOneTimePassword(this.key, this.counter++);
    }

    @Benchmark
    public String benchmarkGenerateOneTimePasswordString() throws InvalidKeyException {
        return this.hotp.generateOneTimePasswordString(this.key, this.counter++);
    }
}

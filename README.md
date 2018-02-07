![Build status](https://travis-ci.org/jchambers/java-otp.svg?branch=master)

java-otp is a library for generating one-time passwords using the [HOTP (RFC 4226)](https://tools.ietf.org/html/rfc4226) or [TOTP (RFC 6238)](https://tools.ietf.org/html/rfc6238) standards in Java.

## Usage

To demonstrate generating one-time passwords, we'll focus on the TOTP algorithm. To create a TOTP generator with a default password length, time step, and HMAC algorithm:

```java
final TimeBasedOneTimePasswordGenerator totp = new TimeBasedOneTimePasswordGenerator();
```

To actually generate time-based one-time passwords, you'll need a secret key and a timestamp. Secure key management is beyond the scope of this document; for the purposes of an example, though, we'll generate a random key:

```java
final Key secretKey;
{
    final KeyGenerator keyGenerator = KeyGenerator.getInstance(totp.getAlgorithm());

    // SHA-1 and SHA-256 prefer 64-byte (512-bit) keys; SHA512 prefers 128-byte keys
    keyGenerator.init(512);

    secretKey = keyGenerator.generateKey();
}
```

Armed with a secret key, we can deterministically generate one-time passwords for any timestamp:

```java
final Date now = new Date();
final Date later = new Date(now.getTime() + TimeUnit.SECONDS.toMillis(30));

System.out.format("Current password: %06d\n", totp.generateOneTimePassword(secretKey, now));
System.out.format("Future password:  %06d\n", totp.generateOneTimePassword(secretKey, later));
```

## License and copyright

java-otp is published under the [MIT License](https://opensource.org/licenses/MIT).

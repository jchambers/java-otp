[![Build status](https://travis-ci.org/jchambers/java-otp.svg?branch=master)](https://travis-ci.org/jchambers/java-otp)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.eatthepath/java-otp/badge.svg)](https://maven-badges.herokuapp.com/maven-central/com.eatthepath/java-otp)

java-otp is a Java library for generating [HOTP (RFC 4226)](https://tools.ietf.org/html/rfc4226) or [TOTP (RFC 6238)](https://tools.ietf.org/html/rfc6238) one-time passwords.

## Getting java-otp

You can download java-otp as a jar file (it has no dependencies) from the [GitHub releases page](https://github.com/jchambers/java-otp/releases) and add it to your project's classpath. If you're using Maven (or something that understands Maven dependencies) to build your project, you can add java-otp as a dependency:

```xml
<dependency>
  <groupId>com.eatthepath</groupId>
  <artifactId>java-otp</artifactId>
  <version>0.2.0</version>
</dependency>
```

java-otp works with Java 8 or newer. If you need support for versions of Java older than Java 8, you may try using [java-otp v0.1](https://github.com/jchambers/java-otp/releases/tag/java-otp-0.1.0) (although it is no longer supported).

## Usage

To demonstrate generating one-time passwords, we'll focus on the TOTP algorithm. To create a TOTP generator with a default password length (6 digits), time step (30 seconds), and HMAC algorithm (HMAC-SHA1):

```java
final TimeBasedOneTimePasswordGenerator totp = new TimeBasedOneTimePasswordGenerator();
```

To actually generate time-based one-time passwords, you'll need a key and a timestamp. Secure key management is beyond the scope of this document; for the purposes of an example, though, we'll generate a random key:

```java
final Key key;
{
    final KeyGenerator keyGenerator = KeyGenerator.getInstance(totp.getAlgorithm());

    // SHA-1 and SHA-256 prefer 64-byte (512-bit) keys; SHA512 prefers 128-byte (1024-bit) keys
    keyGenerator.init(512);

    key = keyGenerator.generateKey();
}
```

Armed with a key, we can deterministically generate one-time passwords for any timestamp:

```java
final Instant now = Instant.now();
final Instant later = now.plus(totp.getTimeStep());

System.out.format("Current password: %06d\n", totp.generateOneTimePassword(key, now));
System.out.format("Future password:  %06d\n", totp.generateOneTimePassword(key, later));
```

…which produces (for one randomly-generated key):

```
Current password: 164092
Future password:  046148
```

## License and copyright

java-otp is published under the [MIT License](https://opensource.org/licenses/MIT).

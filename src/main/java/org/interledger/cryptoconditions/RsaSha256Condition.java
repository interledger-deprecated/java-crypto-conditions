package org.interledger.cryptoconditions;

import static org.interledger.cryptoconditions.CryptoConditionType.RSA_SHA256;

import org.interledger.cryptoconditions.der.DerOutputStream;
import org.interledger.cryptoconditions.der.DerTag;
import org.interledger.cryptoconditions.utils.UnsignedBigInteger;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.interfaces.RSAPublicKey;
import java.util.Objects;

/**
 * Implementation of a condition based on RSA PKI and the SHA-256 function.
 */
public final class RsaSha256Condition extends Sha256Condition implements SimpleCondition {

  /**
   * Constructs an instance of the condition.
   *
   * @param key The RSA public key associated with the condition.
   */
  public RsaSha256Condition(final RSAPublicKey key) {
    super(
        RSA_SHA256,
        calculateCost(key),
        hashFingerprintContents(
            constructFingerprintContents(key)
        )
    );
  }

  /**
   * Constructs an instance of the condition.
   * <p/>
   * Note this constructor is package-private because it is used primarily for testing purposes.
   *
   * @param cost        The calculated cost of the condition.
   * @param fingerprint The calculated fingerprint for the condition.
   */
  RsaSha256Condition(final long cost, final byte[] fingerprint) {
    super(RSA_SHA256, cost, fingerprint);
  }

  /**
   * Constructs the fingerprint for this condition.
   * <p/>
   * Note: This method is package-private as (opposed to private) for testing purposes.
   */
  static final byte[] constructFingerprintContents(final RSAPublicKey publicKey) {
    Objects.requireNonNull(publicKey);
    validatePublicKey(publicKey);

    try {
      // Build modulus
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      DerOutputStream out = new DerOutputStream(baos);
      out.writeTaggedObject(0, UnsignedBigInteger.toUnsignedByteArray(publicKey.getModulus()));
      out.close();
      byte[] buffer = baos.toByteArray();

      // Wrap SEQUENCE
      baos = new ByteArrayOutputStream();
      out = new DerOutputStream(baos);
      out.writeEncoded(DerTag.CONSTRUCTED.getTag() + DerTag.SEQUENCE.getTag(), buffer);
      out.close();
      return baos.toByteArray();

    } catch (IOException e) {
      throw new UncheckedIOException("DER Encoding Error", e);
    }
  }

  /**
   * Calculates the cost of a condition based on an RSA key as ((modulus size in bytes)^2).
   *
   * @param key The key used in the condition.
   * @return the cost of a condition using this key.
   */
  private static final long calculateCost(RSAPublicKey key) {
    return (long) Math.pow(UnsignedBigInteger.toUnsignedByteArray(key.getModulus()).length, 2);
  }

  private static final void validatePublicKey(final RSAPublicKey publicKey) {
    // Validate key
    if (publicKey.getPublicExponent().compareTo(RsaSha256Fulfillment.PUBLIC_EXPONENT) != 0) {
      throw new IllegalArgumentException("Public Exponent of RSA key must be 65537.");
    }

    if (publicKey.getModulus().bitLength() <= 1017 || publicKey.getModulus().bitLength() > 4096) {
      throw new IllegalArgumentException(
          "Modulus of RSA key must be greater than 128 bytes and less than 512 bytes.");
    }
  }
}

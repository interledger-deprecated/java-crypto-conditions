package org.interledger.cryptoconditions.types;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.Sha256Condition;
import org.interledger.cryptoconditions.SimpleCondition;
import org.interledger.cryptoconditions.UnsignedBigInteger;
import org.interledger.cryptoconditions.der.DEROutputStream;
import org.interledger.cryptoconditions.der.DERTags;

public class RsaSha256Condition extends Sha256Condition implements SimpleCondition {

  private RSAPublicKey key;

  public RsaSha256Condition(RSAPublicKey key) {
    super(calculateCost(key));

    // Validate key
    if (key.getPublicExponent().compareTo(RsaSha256Fulfillment.PUBLIC_EXPONENT) != 0) {
      throw new IllegalArgumentException("Public Exponent of RSA key must be 65537.");
    }

    if (key.getModulus().bitLength() <= 1017 || key.getModulus().bitLength() > 4096) {
      throw new IllegalArgumentException(
          "Modulus of RSA key must be greater than 128 bytes and less than 512 bytes.");
    }

    this.key = key;
  }

  public RsaSha256Condition(byte[] fingerprint, long cost) {
    super(fingerprint, cost);
  }

  @Override
  public ConditionType getType() {
    return ConditionType.RSA_SHA256;
  }

  @Override
  protected byte[] getFingerprintContents() {
    try {
      // Build modulus
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      DEROutputStream out = new DEROutputStream(baos);
      out.writeTaggedObject(0, UnsignedBigInteger.toUnsignedByteArray(key.getModulus()));
      out.close();
      byte[] buffer = baos.toByteArray();

      // Wrap SEQUENCE
      baos = new ByteArrayOutputStream();
      out = new DEROutputStream(baos);
      out.writeEncoded(DERTags.CONSTRUCTED.getTag() + DERTags.SEQUENCE.getTag(), buffer);
      out.close();
      return baos.toByteArray();

    } catch (IOException e) {
      throw new UncheckedIOException("DER Encoding Error", e);
    }
  }

  /**
   * cost = (modulus size in bytes) ^ 2
   * 
   * @param key
   * @return cost
   */
  private static long calculateCost(RSAPublicKey key) {
    return (long) Math.pow(UnsignedBigInteger.toUnsignedByteArray(key.getModulus()).length, 2);
  }
}

package org.interledger.cryptoconditions.types;

import net.i2p.crypto.eddsa.EdDSAPublicKey;

import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.Sha256Condition;
import org.interledger.cryptoconditions.SimpleCondition;
import org.interledger.cryptoconditions.der.DerOutputStream;
import org.interledger.cryptoconditions.der.DerTag;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;

/**
 * Implementation of a crypto-condition using the ED-25519 and SHA-256 functions.
 */
public class Ed25519Sha256Condition extends Sha256Condition implements SimpleCondition {

  private EdDSAPublicKey key;

  /**
   * Constructs an instance of the condition.
   * 
   * @param key The public key to use when creating the fingerprint.
   */
  public Ed25519Sha256Condition(EdDSAPublicKey key) {
    super(calculateCost(key));
    // TODO Validate key

    this.key = key;
  }

  /**
   * Constructs an instance of the condition with the given fingerprint and cost.
   * 
   * @param fingerprint The fingerprint associated with the condition.
   * @param cost    The cost associated with the condition.
   */
  public Ed25519Sha256Condition(byte[] fingerprint, long cost) {
    super(fingerprint, cost);
  }

  @Override
  public ConditionType getType() {
    return ConditionType.ED25519_SHA256;
  }

  @Override
  protected byte[] getFingerprintContents() {
    try {
      // Write public key
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      DerOutputStream out = new DerOutputStream(baos);
      out.writeTaggedObject(0, key.getA().toByteArray());
      out.close();
      byte[] buffer = baos.toByteArray();

      // Wrap SEQUENCE
      baos = new ByteArrayOutputStream();
      out = new DerOutputStream(baos);
      out.writeEncoded(DerTag.CONSTRUCTED.getTag() + DerTag.SEQUENCE.getTag(), buffer);
      out.close();
      return baos.toByteArray();

    } catch (IOException ioe) {
      throw new UncheckedIOException("DER Encoding Error", ioe);
    }
  }

  /**
   * Returns the cost of the condition (131072).
   * 
   * @param key the key used in the condition.
   * @return the cost of the condition
   */
  private static long calculateCost(EdDSAPublicKey key) {
    return 131072; //TODO: is this a placehoder, or should it be a constant?
  }
}

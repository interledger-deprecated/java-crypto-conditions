package org.interledger.cryptoconditions.types;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;

import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.Sha256Condition;
import org.interledger.cryptoconditions.SimpleCondition;
import org.interledger.cryptoconditions.der.DEROutputStream;
import org.interledger.cryptoconditions.der.DERTags;

import net.i2p.crypto.eddsa.EdDSAPublicKey;

public class Ed25519Sha256Condition extends Sha256Condition implements SimpleCondition {

  private EdDSAPublicKey key;

  public Ed25519Sha256Condition(EdDSAPublicKey key) {
    super(calculateCost(key));
    // TODO Validate key

    this.key = key;
  }

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
      DEROutputStream out = new DEROutputStream(baos);
      out.writeTaggedObject(0, key.getA().toByteArray());
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
   * cost = 131072
   * 
   * @param key
   * @return cost
   */
  private static long calculateCost(EdDSAPublicKey key) {
    return 131072;
  }
}

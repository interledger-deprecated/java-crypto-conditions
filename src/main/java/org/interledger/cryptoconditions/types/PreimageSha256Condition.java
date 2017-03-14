package org.interledger.cryptoconditions.types;

import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.Sha256Condition;
import org.interledger.cryptoconditions.SimpleCondition;

/**
 * Implementation of a condition based on a preimage and the SHA-256 function.
 */
public class PreimageSha256Condition extends Sha256Condition implements SimpleCondition {

  private byte[] preimage;

  /**
   * Constructs an instance of the condition.
   * 
   * @param preimage The preimage associated with this condition.
   */
  public PreimageSha256Condition(byte[] preimage) {
    super(calculateCost(preimage));
    this.preimage = new byte[preimage.length];
    System.arraycopy(preimage, 0, this.preimage, 0, preimage.length);
  }

  /**
   * Constructs an instance of the condition.
   * 
   * @param fingerprint The calculated fingerprint for the condition.
   * @param cost The cost associated with this condition.
   */
  public PreimageSha256Condition(byte[] fingerprint, long cost) {
    super(fingerprint, cost);
  }

  @Override
  public ConditionType getType() {
    return ConditionType.PREIMAGE_SHA256;
  }

  /**
   * The PreimageSha256 fingerprint is the SHA256 hash of the raw preimage.
   */
  @Override
  protected byte[] getFingerprintContents() {
    return preimage;
  }

  /**
   * Calculates the cost of this condition, which is simply the length of the preimage.
   * 
   * @param preimage The preimage associated with this condition.
   * @return The cost of a condition based on the preimage.
   */
  private static long calculateCost(byte[] preimage) {
    return preimage.length;
  }

}

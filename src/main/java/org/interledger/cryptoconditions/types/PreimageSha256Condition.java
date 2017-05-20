package org.interledger.cryptoconditions.types;

import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.Sha256Condition;
import org.interledger.cryptoconditions.SimpleCondition;

import java.util.Arrays;

/**
 * This type of condition is also called a "hashlock".  By creating a hash of a difficult-to-guess,
 * 256-bit, random or pseudo-random integer, it is possible to create a condition which the creator
 * can trivially fulfill by publishing the random value used to create the condition (the
 * original random value is also referred to as a "preimage"). For anyone else, a hashlock
 * condition is cryptographically hard to fulfill because one would have to find a preimage for
 * the given condition hash.
 */
public class PreimageSha256Condition extends Sha256Condition implements SimpleCondition {

  private final byte[] preimage;

  /**
   * Required-args Constructor.  Constructs an instance of {@link PreimageSha256Condition} based
   * on a supplied preimage. This constructor variant is intended to be used by developers
   * wishing to construct a Preimage condition from a secret preimage.
   *
   * @param preimage An instance of {@link byte[]} containing preimage data.
   */
  public PreimageSha256Condition(final byte[] preimage) {
    super(calculateCost(preimage));
    this.preimage = Arrays.copyOf(preimage, preimage.length);
  }

  /**
   * Constructs an instance of {@link PreimageSha256Condition} using a fingerprint and cost. Note
   * that this constructor variant does not include a preimage, and is thus intended to be used
   * to construct a condition that does not include a preimage (for example, if a condition is
   * supplied by a remote system).
   *
   * @param fingerprint An instance of {@link byte[]} that contains the calculated fingerprint for
   *     the condition.
   * @param cost The cost associated with this condition.
   */
  public PreimageSha256Condition(byte[] fingerprint, long cost) {
    super(fingerprint, cost);
    this.preimage = null;
  }

  @Override
  public ConditionType getType() {
    return ConditionType.PREIMAGE_SHA256;
  }

  /**
   * For instances of {@link PreimageSha256Condition}, the fingerprint of a PREIMAGE-SHA-256
   * condition is the SHA-256 hash of the *unencoded* preimage.  Thus, this method returns the
   * preimage.
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
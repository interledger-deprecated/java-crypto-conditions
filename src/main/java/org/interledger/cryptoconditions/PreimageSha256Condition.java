package org.interledger.cryptoconditions;

import static org.interledger.cryptoconditions.CryptoConditionType.PREIMAGE_SHA256;

import java.util.Objects;

/**
 * This type of condition is also called a "hashlock".  By creating a hash of a difficult-to-guess,
 * 256-bit, random or pseudo-random integer, it is possible to create a condition which the creator
 * can trivially fulfill by publishing the random value used to create the condition (the
 * original random value is also referred to as a "preimage"). For anyone else, a hashlock
 * condition is cryptographically hard to fulfill because one would have to find a preimage for
 * the given condition hash.
 */
public final class PreimageSha256Condition extends Sha256Condition implements SimpleCondition {

  /**
   * Required-args Constructor.  Constructs an instance of {@link PreimageSha256Condition} based
   * on a supplied preimage. This constructor variant is intended to be used by developers
   * wishing to construct a Preimage condition from a secret preimage.
   *
   * @param preimage An instance of byte array containing preimage data.
   */
  public PreimageSha256Condition(final byte[] preimage) {
    super(
        CryptoConditionType.PREIMAGE_SHA256,
        calculateCost(preimage),
        hashFingerprintContents(
            constructFingerprintContents(preimage)
        )
    );
  }

  /**
   * Constructs an instance of {@link PreimageSha256Condition} using a fingerprint and cost. Note
   * that this constructor variant does not include a preimage, and is thus intended to be used
   * to construct a condition that does not include a preimage (for example, if a condition is
   * supplied by a remote system).
   * <p/>
   * Note this constructor is package-private because it is used primarily for testing purposes.
   *
   * @param cost        The cost associated with this condition.
   * @param fingerprint An instance of byte array that contains the calculated fingerprint for
   */
  PreimageSha256Condition(final long cost, final byte[] fingerprint) {
    super(PREIMAGE_SHA256, cost, fingerprint);
  }

  /**
   * Constructs the fingerprint for this condition.
   * <p/>
   * Note: This method is package-private as (opposed to private) for testing purposes.
   */
  static final byte[] constructFingerprintContents(final byte[] prefix) {
    return Objects.requireNonNull(prefix);
  }

  /**
   * Calculates the cost of this condition, which is simply the length of the preimage.
   *
   * @param preimage The preimage associated with this condition.
   * @return The cost of a condition based on the preimage.
   */
  private static final long calculateCost(byte[] preimage) {
    return preimage.length;
  }

}
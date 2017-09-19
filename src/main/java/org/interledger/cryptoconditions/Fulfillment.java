package org.interledger.cryptoconditions;

/**
 * An implementation of a crypto-conditions Fulfillment.
 *
 * @see "https://datatracker.ietf.org/doc/draft-thomas-crypto-conditions/"
 */
public interface Fulfillment<C extends Condition> {

  /**
   * Accessor for the type of this fulfillment.
   *
   * @return A {@link CryptoConditionType} for this fulfillment.
   */
  CryptoConditionType getType();

  /**
   * Accessor for the condition that corresponds to this fulfillment.
   *
   * @return A {@link Condition} that can be fulfilled by this fulfillment.
   */
  C getCondition();

  /**
   * Verify that this fulfillment validates the supplied {@code condition}. A fulfillment is
   * validated by evaluating that the circuit output is {@code true} but also that the provided
   * fulfillment matches the circuit fingerprint, which is the  {@code condition}.
   *
   * @param condition A {@link Condition} that this fulfillment should validate.
   * @param message   A byte array that is part of verifying the supplied condition.
   * @return {@code true} if this fulfillment validates the supplied condition and message; {@code
   * false} otherwise.
   */
  boolean verify(C condition, byte[] message);

}

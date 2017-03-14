package org.interledger.cryptoconditions.types;

import org.interledger.cryptoconditions.CompoundCondition;
import org.interledger.cryptoconditions.CompoundSha256Condition;
import org.interledger.cryptoconditions.Condition;
import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.der.DerOutputStream;
import org.interledger.cryptoconditions.der.DerTag;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.util.EnumSet;

/**
 * Implementation of a crypto condition based on a prefix, a sub-condition and the SHA-256 function.
 */
public class PrefixSha256Condition extends CompoundSha256Condition implements CompoundCondition {

  private byte[] prefix;
  private long maxMessageLength;
  private Condition subcondition;

  /**
   * Constructs an instance of the condition.
   * 
   * @param prefix The prefix to use when creating the fingerprint.
   * @param maxMessageLength The maximum length of the message.
   * @param subcondition A condition on which this condition depends.
   */
  public PrefixSha256Condition(byte[] prefix, long maxMessageLength, Condition subcondition) {
    super(calculateCost(prefix, maxMessageLength, subcondition.getCost()),
        calculateSubtypes(subcondition));
    this.prefix = new byte[prefix.length];
    System.arraycopy(prefix, 0, this.prefix, 0, prefix.length);
    this.maxMessageLength = maxMessageLength;
    this.subcondition = subcondition;
  }

  /**
   * Constructs an instance of the condition.
   * 
   * @param fingerprint The calculated fingerprint.
   * @param cost The cost of this condition.
   * @param subtypes A set of condition types for the conditions that this one depends on.
   */
  public PrefixSha256Condition(byte[] fingerprint, long cost, EnumSet<ConditionType> subtypes) {
    super(fingerprint, cost, subtypes);
  }

  @Override
  public ConditionType getType() {
    return ConditionType.PREFIX_SHA256;
  }

  @Override
  protected byte[] getFingerprintContents() {

    try {
      // Build prefix and subcondition
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      DerOutputStream out = new DerOutputStream(baos);
      out.writeTaggedObject(0, prefix);
      out.writeTaggedObject(1, BigInteger.valueOf(maxMessageLength).toByteArray());
      out.writeTaggedConstructedObject(2, subcondition.getEncoded());
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
   * Determines the cost associated with this condition. This is determined as length_of_prefix +
   * max_message_length + subcondition_cost + 1024
   * 
   * @param prefix The prefix included in this condition.
   * @param maxMessageLength The maximum length of the message.
   * @param subconditionCost The cost of the sub condition.
   * @return The calculated cost of this condition.
   */
  private static long calculateCost(byte[] prefix, long maxMessageLength, long subconditionCost) {

    return prefix.length + maxMessageLength + subconditionCost + 1024;
  }

  /**
   * Determines the set of condition types that are ultimately held via the sub condition.
   * 
   * @param subcondition The sub condition that this condition depends on.
   * @return The set of condition types related to the sub condition.
   */
  private static EnumSet<ConditionType> calculateSubtypes(Condition subcondition) {
    EnumSet<ConditionType> subtypes = EnumSet.of(subcondition.getType());
    if (subcondition instanceof CompoundCondition) {
      subtypes.addAll(((CompoundCondition) subcondition).getSubtypes());
    }

    // Remove our own type
    if (subtypes.contains(ConditionType.PREFIX_SHA256)) {
      subtypes.remove(ConditionType.PREFIX_SHA256);
    }

    return subtypes;
  }

}

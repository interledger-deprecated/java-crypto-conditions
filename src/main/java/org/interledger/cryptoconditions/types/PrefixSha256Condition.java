package org.interledger.cryptoconditions.types;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.util.EnumSet;

import org.interledger.cryptoconditions.CompoundCondition;
import org.interledger.cryptoconditions.CompoundSha256Condition;
import org.interledger.cryptoconditions.Condition;
import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.der.DEROutputStream;
import org.interledger.cryptoconditions.der.DERTags;

public class PrefixSha256Condition extends CompoundSha256Condition implements CompoundCondition {

  private byte[] prefix;
  private long maxMessageLength;
  private Condition subcondition;

  public PrefixSha256Condition(byte[] prefix, long maxMessageLength, Condition subcondition) {
    super(calculateCost(prefix, maxMessageLength, subcondition.getCost()), calculateSubtypes(subcondition));
    this.prefix = new byte[prefix.length];
    System.arraycopy(prefix, 0, this.prefix, 0, prefix.length);
    this.maxMessageLength = maxMessageLength;
    this.subcondition = subcondition;
  }

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
      DEROutputStream out = new DEROutputStream(baos);
      out.writeOctetString(prefix);
      out.writeInteger(BigInteger.valueOf(maxMessageLength));
      out.writeOctetString(subcondition.getEncoded());
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
   * cost = length_of_prefix + max_message_length + subcondition_cost + 1024
   * 
   * @param prefix
   * @param maxMessageLength
   * @param subconditionCost
   * @return
   */
  private static long calculateCost(byte[] prefix, long maxMessageLength, long subconditionCost) {

    return prefix.length + maxMessageLength + subconditionCost + 1024l;
  }

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

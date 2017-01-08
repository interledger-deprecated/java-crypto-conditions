package org.interledger.cryptoconditions;

import java.util.EnumSet;

public abstract class CompoundSha256Condition extends Sha256Condition implements CompoundCondition {

  private EnumSet<ConditionType> subtypes;
  
  protected CompoundSha256Condition(long cost, EnumSet<ConditionType> subtypes) {
    super(cost);
    this.subtypes = EnumSet.copyOf(subtypes);
  }

  protected CompoundSha256Condition(byte[] fingerprint, long cost, EnumSet<ConditionType> subtypes) {
    super(fingerprint, cost);
    this.subtypes = EnumSet.copyOf(subtypes);
  }

  @Override
  public EnumSet<ConditionType> getSubtypes() {
    return EnumSet.copyOf(subtypes);
  }

}

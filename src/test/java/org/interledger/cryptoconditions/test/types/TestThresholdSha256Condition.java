package org.interledger.cryptoconditions.test.types;

import org.interledger.cryptoconditions.Condition;
import org.interledger.cryptoconditions.test.TestCondition;
import org.interledger.cryptoconditions.types.ThresholdSha256Condition;

public class TestThresholdSha256Condition extends ThresholdSha256Condition implements TestCondition {

  public TestThresholdSha256Condition(int threshold, Condition[] subconditions) {
    super(threshold, subconditions);
  }

  public byte[] getUnhashedFingerprint() {
    return getFingerprintContents();
  }
  
}

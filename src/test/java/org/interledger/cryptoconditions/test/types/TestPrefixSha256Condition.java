package org.interledger.cryptoconditions.test.types;

import org.interledger.cryptoconditions.Condition;
import org.interledger.cryptoconditions.test.TestCondition;
import org.interledger.cryptoconditions.types.PrefixSha256Condition;

public class TestPrefixSha256Condition extends PrefixSha256Condition implements TestCondition {

  public TestPrefixSha256Condition(byte[] prefix, long maxMessageLength, Condition subcondition) {
    super(prefix, maxMessageLength, subcondition);
  }

  public byte[] getUnhashedFingerprint() {
    return getFingerprintContents();
  }
  
}

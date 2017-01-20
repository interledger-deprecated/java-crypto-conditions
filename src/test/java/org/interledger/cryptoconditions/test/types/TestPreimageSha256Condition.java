package org.interledger.cryptoconditions.test.types;

import org.interledger.cryptoconditions.test.TestCondition;
import org.interledger.cryptoconditions.types.PreimageSha256Condition;

public class TestPreimageSha256Condition extends PreimageSha256Condition implements TestCondition {
  
  public TestPreimageSha256Condition(byte[] preimage) {
    super(preimage);
  }

  public byte[] getUnhashedFingerprint() {
    return getFingerprintContents();
  }
  
}

package org.interledger.cryptoconditions.test.types;

import org.interledger.cryptoconditions.test.TestCondition;
import org.interledger.cryptoconditions.types.RsaSha256Condition;

import java.security.interfaces.RSAPublicKey;

public class TestRsaSha256Condition extends RsaSha256Condition implements TestCondition {

  public TestRsaSha256Condition(RSAPublicKey key) {
    super(key);
  }

  public byte[] getUnhashedFingerprint() {
    return getFingerprintContents();
  }
  
}

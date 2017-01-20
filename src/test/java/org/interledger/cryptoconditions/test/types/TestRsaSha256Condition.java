package org.interledger.cryptoconditions.test.types;

import java.security.interfaces.RSAPublicKey;

import org.interledger.cryptoconditions.test.TestCondition;
import org.interledger.cryptoconditions.types.RsaSha256Condition;

public class TestRsaSha256Condition extends RsaSha256Condition implements TestCondition {

  public TestRsaSha256Condition(RSAPublicKey key) {
    super(key);
  }

  public byte[] getUnhashedFingerprint() {
    return getFingerprintContents();
  }
  
}

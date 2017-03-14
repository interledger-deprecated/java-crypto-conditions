package org.interledger.cryptoconditions.test.types;

import net.i2p.crypto.eddsa.EdDSAPublicKey;

import org.interledger.cryptoconditions.test.TestCondition;
import org.interledger.cryptoconditions.types.Ed25519Sha256Condition;

public class TestEd25519Sha256Condition extends Ed25519Sha256Condition implements TestCondition {

  public TestEd25519Sha256Condition(EdDSAPublicKey key) {
    super(key);
  }

  public byte[] getUnhashedFingerprint() {
    return getFingerprintContents();
  }
  
}

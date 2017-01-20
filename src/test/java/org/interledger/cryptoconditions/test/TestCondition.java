package org.interledger.cryptoconditions.test;

import org.interledger.cryptoconditions.Condition;

public interface TestCondition extends Condition {
  
  byte[] getUnhashedFingerprint();
  
}

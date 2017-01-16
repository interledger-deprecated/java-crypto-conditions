package org.interledger.cryptoconditions;

public interface Fulfillment {

  ConditionType getType();

  byte[] getEncoded();

  Condition getCondition();

  boolean verify(Condition condition, byte[] message);

}

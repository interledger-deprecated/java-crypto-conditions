package org.interledger.cryptoconditions.test;

import java.util.EnumSet;
import java.util.List;

import org.interledger.cryptoconditions.Condition;
import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.Fulfillment;

public class CryptoConditionAssert {

  static public void assertSetOfTypesIsEqual(String message, List<String> expected, EnumSet<ConditionType> actual) {
    EnumSet<ConditionType> expectedSet = ConditionType.getEnumOfTypesFromString(
        String.join(",", expected.toArray(new String[expected.size()])));
    
    if(!expectedSet.containsAll(actual)) {
      throw new AssertionError(message + " - expected does not contain all values from actual.");
    };
    expectedSet.removeAll(actual);
    if(!expectedSet.isEmpty()){
      throw new AssertionError(message + " - expected contains values not in actual.");
    }
  }
  
  public static void assertFulfillmentIsvalidForCondition(String assertionMessage, Fulfillment fulfillment, Condition condition, byte[] message) {
    if(!fulfillment.verify(condition, message)){
      if(!fulfillment.getCondition().equals(condition)) {
        throw new AssertionError(assertionMessage + " - derived condition is not equal to generated condition.");
      }
      throw new AssertionError(assertionMessage + " - verify return false.");
    }
  }

}

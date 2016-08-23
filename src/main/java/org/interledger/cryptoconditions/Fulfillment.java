package org.interledger.cryptoconditions;

/**
 * Fulfillments are cryptographically verifiable messages that prove an event occurred. 
 * 
 * If you transmit a fulfillment, then everyone who has the condition can agree that 
 * the condition has been met.
 * 
 * A fulfillment fulfills a Condition. 
 * 
 * The fulfillment payload and condition type can be used to regenerate the condition
 * so that it is possible to compare the fingerprint of the condition.
 * 
 * @author adrianhopebailie
 *
 */
public interface Fulfillment {
	
	/**
	 * Get the type of condition that is fulfilled by this fulfillment
	 * 
	 * @see ConditionType
	 * 
	 * @return the type of the condition that this fulfills
	 */
	ConditionType getType();
		
	/**
	 * Get the fulfillment data
	 * 
	 * @return raw bytes representing the fulfillment
	 */
	byte[] getPayload();
			
}

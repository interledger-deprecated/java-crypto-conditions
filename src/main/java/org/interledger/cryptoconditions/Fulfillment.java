package org.interledger.cryptoconditions;

/**
 * A fulfillment fulfills a crypto-condition. 
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
	ConditionType getTypeID();
		
	/**
	 * Get the fulfillment data
	 * 
	 * @return raw bytes representing the fulfillment
	 */
	byte[] getPayload();
			
	/**
	 * Generate the condition that this fulfillment fulfills
	 * 
	 * @return
	 */
	Condition generateCondition();

	//TODO Should this be on the interface?
	//int calculateMaxFullfilmentSize();

	/**
	 * Get a binary OER encoded representation of this fulfillment
	 * 
	 * TODO - Add encoding format
	 * 
	 * @return OER encoded fulfillment
	 */
	byte[] toBinary();

	/**
	 * Get a string encoded representation of this fulfillment
	 * 
	 * TODO - Add encoding format
	 * 
	 * @return string encoded fulfillment
	 */
	String toString();

}

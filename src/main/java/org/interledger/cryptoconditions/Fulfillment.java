package org.interledger.cryptoconditions;

import java.util.EnumSet;

import org.interledger.cryptoconditions.types.*;
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
public interface Fulfillment  {
    
    /**
     * Get the type of condition that is fulfilled by this fulfillment
     * 
     * @see ConditionType
     * 
     * @return the type of the condition that this fulfills
     */
    ConditionType getType();
    
    /**
     * Get the features requited for this fulfillment
     * 
     * @see FeatureSuite
     * 
     * @return the type of the condition that this fulfills
     */
    EnumSet<FeatureSuite> getFeatures();
        
    /**
     * Get the fulfillment data
     * 
     * @return raw bytes representing the fulfillment
     */
    FulfillmentPayload getPayload();
            
    
    /**
     * Generate the condition for this fulfillment
     * 
     * This may be a computationally intensive operation as it will 
     * recurse through sub-fulfillments as required to generate sub-conditions.
     * 
     * @return a Condition that is fulfilled by this object
     */
    // TODO:(0) make private. Only getCondition must call it. 
    Condition generateCondition();
    
    Condition getCondition();
    
    /**
     * Serialize/Print to string the fulfillment
     * 
     * @return (ASCII-)URI representation of the Fulfillment
     */
    public String toURI();
    
    /**
     * Validate this fulfillment.
     * 
     * Final classes must implement this method.
     * 
     * @return {boolean} Validation result 
     */
    public boolean validate(MessagePayload message);

    /*
     * TODO:(0)
     * Once the fulfillment has been generated, it's a good
     * practice to clear the secret (preimage, private password, ...)
     */
    // public void clearSecrets();

}

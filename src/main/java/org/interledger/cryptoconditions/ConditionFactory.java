package org.interledger.cryptoconditions;

/**
 * Generates appropriate conditions from fulfillments
 * 
 * @author adrianhopebailie
 *
 */
public class ConditionFactory {

	public static Condition fromFulfillment(Fulfillment fulfillment){
		switch (fulfillment.getType()){
		case PREIMAGE_SHA256:
			if(!fulfillment.getClass().equals(PreimageSha256Fulfillment.class))
				throw new IllegalArgumentException("Invalid fulfillment type. Expecting PreimageSha256Fulfillment.");
				
			return PreimageSha256Condition.fromFulfillment((PreimageSha256Fulfillment) fulfillment);
			
		case PREFIX_SHA256:
			if(!fulfillment.getClass().equals(PrefixSha256Fulfillment.class))
				throw new IllegalArgumentException("Invalid fulfillment type. Expecting PrefixSha256Fulfillment.");
				
			return PrefixSha256Condition.fromFulfillment((PrefixSha256Fulfillment) fulfillment);
			
		case RSA_SHA256:
			//TODO Implement 
		case ED25519:
			//TODO Implement 
		case THRESHOLD_SHA256:
			//TODO Implement 
		default:
			throw new RuntimeException("Unimplemented feature.");
		}
		
	}
	
	
}

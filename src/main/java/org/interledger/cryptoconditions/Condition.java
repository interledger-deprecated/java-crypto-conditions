package org.interledger.cryptoconditions;

import java.util.EnumSet;

public interface Condition {	
	
	ConditionType getType();
	
	EnumSet<FeatureSuite> getFeatures();
	
	byte[] getFingerprint();
	
	int getMaxFulfillmentLength();
	
	byte[] toBinary();
	
	String toString();	
}

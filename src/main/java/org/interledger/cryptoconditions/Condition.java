package org.interledger.cryptoconditions;

import java.net.URI;
import java.util.EnumSet;

public interface Condition {	
	
	ConditionType getType();
	
	EnumSet<FeatureSuite> getFeatures();
	
	byte[] getFingerprint();
	
	int getMaxFulfillmentLength();
	
	URI toURI(); //TODO Should this just return a String?
	
	byte[] toBinary();
	
}

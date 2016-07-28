package org.interledger.cryptoconditions;

import java.net.URI;
import java.util.EnumSet;

public interface Fullfilment {
	
	ConditionType getTypeID();
	
	EnumSet<FeatureSuite> getFeatures();
	
	byte[] getHash();
		
	URI toURI();
	
	byte[] toBinary();
	
	Condition generateCondition();
	
	int calculateMaxFullfilmentSize();
	
}

package org.interledger.cryptoconditions;

import java.util.EnumSet;

import org.interledger.cryptoconditions.Condition;
import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.FeatureSuite;

final class ConditionImpl implements Condition {

	private final ConditionType type;
	private final EnumSet<FeatureSuite> features;
	private final byte[] fingerprint;
	private final int maxFulfillmentLength;

	public ConditionImpl(ConditionType type, EnumSet<FeatureSuite> features, byte[] fingerprint,  
			int maxFulfillmentLength) {
		if (type == null) 
			throw new IllegalArgumentException("Type cannot be null.");
		if (fingerprint == null) 
			throw new IllegalArgumentException("Fingerprint cannot be null.");
		if (features == null) 
			throw new IllegalArgumentException("Features cannot be null.");
		if (maxFulfillmentLength < 0) 
			throw new IllegalArgumentException("MaxFulfillmentLength can't be negative.");
		
		// TODO:(0) maxFulfillmentLength can be empty/zero-length ?
		// TODO:(0) fingerprint          can be empty/zero-length ?
		// TODO:(0) features.isEmpty()   allowed ?

		this.type = type;
		this.fingerprint = fingerprint;
		this.features = features;
		this.maxFulfillmentLength = maxFulfillmentLength;
	}

	public ConditionType getType() {
		return this.type;
	}
	

	public EnumSet<FeatureSuite> getFeatures(){
		return this.features;
	}
	

	public byte[] getFingerprint(){
		return this.fingerprint;
	}

	public int getMaxFulfillmentLength() {
		return this.maxFulfillmentLength;
	}
}
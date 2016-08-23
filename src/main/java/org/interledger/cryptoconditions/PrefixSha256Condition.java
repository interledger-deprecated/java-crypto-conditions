package org.interledger.cryptoconditions;

import java.util.EnumSet;

/**
 * Implementation of a PREFIX-SHA-256 crypto-condition
 * 
 * @author adrianhopebailie
 *
 */
public class PrefixSha256Condition implements Condition {

	public static EnumSet<FeatureSuite> BASE_FEATURES = EnumSet.of(FeatureSuite.SHA_256, FeatureSuite.PREFIX);
	
	private EnumSet<FeatureSuite> features;
	private byte[] fingerprint;
	private int maxFulfillmentLength;
		
	public PrefixSha256Condition(byte[] fingerprint, EnumSet<FeatureSuite> subcondtion_features, 
			int maxFulfillmentLength) {
		
		this.fingerprint = fingerprint;
		
		this.features = BASE_FEATURES.clone();
		this.features.addAll(subcondtion_features);
		
		this.maxFulfillmentLength = maxFulfillmentLength;
	}
	
	@Override
	public ConditionType getType() {
		return ConditionType.PREFIX_SHA256;
	}

	@Override
	public EnumSet<FeatureSuite> getFeatures() {
		return features;
	}

	@Override
	public byte[] getFingerprint() {
		return fingerprint;
	}

	@Override
	public int getMaxFulfillmentLength() {
		return maxFulfillmentLength;
	}
	
}

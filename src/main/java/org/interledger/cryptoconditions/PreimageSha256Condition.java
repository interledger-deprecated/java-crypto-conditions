package org.interledger.cryptoconditions;

import java.util.EnumSet;

import org.interledger.cryptoconditions.util.Crypto;

/**
 * Implementation of a PREIMAGE-SHA-256 crypto-condition
 * 
 * @author adrianhopebailie
 *
 */
public class PreimageSha256Condition implements Condition {

	private byte[] fingerprint;
	private int maxFulfillmentLength;
		
	public PreimageSha256Condition(byte[] fingerprint, int maxFulfillmentLength) {
		this.fingerprint = fingerprint;
		this.maxFulfillmentLength = maxFulfillmentLength;
	}
	
	@Override
	public ConditionType getType() {
		return ConditionType.PREIMAGE_SHA256;
	}

	@Override
	public EnumSet<FeatureSuite> getFeatures() {
		return EnumSet.of(FeatureSuite.SHA_256, FeatureSuite.PREIMAGE);
	}

	@Override
	public byte[] getFingerprint() {
		return fingerprint;
	}

	@Override
	public int getMaxFulfillmentLength() {
		return maxFulfillmentLength;
	}

	public static PreimageSha256Condition fromFulfillment(PreimageSha256Fulfillment fulfillment) {
		byte[] fingerprint = Crypto.getSha256Hash(fulfillment.getPreimage());
		int maxFulfillmentLength = fulfillment.getPreimage().length;
		return new PreimageSha256Condition(fingerprint, maxFulfillmentLength);
	}
	

}

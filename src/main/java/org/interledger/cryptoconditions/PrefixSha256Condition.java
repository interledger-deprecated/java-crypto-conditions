package org.interledger.cryptoconditions;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.EnumSet;

import org.interledger.cryptoconditions.encoding.ConditionOutputStream;
import org.interledger.cryptoconditions.util.Crypto;

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
		
	public PrefixSha256Condition(byte[] fingerprint, EnumSet<FeatureSuite> features, 
			int maxFulfillmentLength) {
		this.fingerprint = fingerprint;
		this.features = features;
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
	
	public static PrefixSha256Condition fromFulfillment(PrefixSha256Fulfillment fulfillment) {
		
		Condition subcondition = ConditionFactory.fromFulfillment(fulfillment.getSubFulfillment());
		
		EnumSet<FeatureSuite> features = EnumSet.copyOf(BASE_FEATURES);
		features.addAll(subcondition.getFeatures());
		
		byte[] fingerprint = Crypto.getSha256Hash(
				calculateFingerPrintContent(
					fulfillment.getPrefix(), 
					subcondition
				)
			);
		
		int maxFulfillmentLength = calculateMaxFulfillmentLength(
				fulfillment.getPrefix(), 
				subcondition
			);
		
		return new PrefixSha256Condition(fingerprint, features, maxFulfillmentLength);
	}
	
	private static byte[] calculateFingerPrintContent(byte[] prefix, Condition subcondition)
	{
		
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		ConditionOutputStream stream = new ConditionOutputStream(buffer);
		
		try {
			stream.writeOctetString(prefix);
			stream.writeCondition(subcondition);
			stream.flush();
			return buffer.toByteArray();
		} catch (IOException e) {
			throw new RuntimeException(e);
		} finally {
			try {
				stream.close();
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}
	}
	
	private static int calculateMaxFulfillmentLength(byte[] prefix, Condition subcondition)
	{
		int length = prefix.length;
		if(length < 128)
		{
			length = length + 1;
		} else if(length <= 255) {
			length = length + 2;
		} else if (length <= 65535) {
			length = length + 3;
		} else if (length <= 16777215){
			length = length + 4;
		} else {
			throw new IllegalArgumentException("Field lengths of greater than 16777215 are not supported.");
		}
		return length + subcondition.getMaxFulfillmentLength();
	}

}

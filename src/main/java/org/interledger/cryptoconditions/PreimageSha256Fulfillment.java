package org.interledger.cryptoconditions;

import org.interledger.cryptoconditions.util.Crypto;

/**
 * Implementation of a PREIMAGE-SHA-256 crypto-condition fulfillment
 * 
 * TODO Safe synchronized access to members?
 * 
 * @author adrianhopebailie
 *
 */
public class PreimageSha256Fulfillment implements Fulfillment<PreimageSha256Condition> {
	
	private byte[] preimage;
			
	public PreimageSha256Fulfillment(byte[] preimage) {
		setPreimage(preimage);
	}

	public void setPreimage(byte[] preimage)
	{
		//TODO - Should this be immutable? Use ArrayCopy?
		this.preimage = preimage;
	}
	
	public byte[] getPreimage() {
		//TODO - Should this object be immutable? Use ArrayCopy?
		return preimage;
	}
	
	@Override
	public ConditionType getType() {
		return ConditionType.PREIMAGE_SHA256;
	}

	@Override
	public byte[] getPayload() {
		return getPreimage();
	}

	@Override
	public PreimageSha256Condition generateCondition() {
		byte[] fingerprint = Crypto.getSha256Hash(preimage);
		int maxFulfillmentLength = preimage.length;
		return new PreimageSha256Condition(fingerprint, maxFulfillmentLength);
	}
}

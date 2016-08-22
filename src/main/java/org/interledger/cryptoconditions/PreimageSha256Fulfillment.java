package org.interledger.cryptoconditions;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.EnumSet;

import org.interledger.cryptoconditions.encoding.ConditionOutputStream;
import org.interledger.cryptoconditions.util.Crypto;

public class PreimageSha256Fulfillment implements Fulfillment {
	
	private byte[] preimage;
	
	public PreimageSha256Fulfillment() {
		preimage = new byte[0];
	}
	
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
	public ConditionType getTypeID() {
		return ConditionType.PREIMAGE_SHA256;
	}

	@Override
	public byte[] getPayload() {
		//TODO - does this need a length prefix?
		return getPreimage();
	}

	@Override
	public String toString() {
		// TODO string encoding
		return null;
	}

	@Override
	public byte[] toBinary() {
		// TODO OER encoding
		return null;
	}

	@Override
	public Condition generateCondition() {
		final byte[] fingerprint = Crypto.getSha256Hash(this.preimage);
		
		return new Condition() {
			
			@Override
			public String toString() {
				// TODO string encoding
				return null;
			}
			
			@Override
			public byte[] toBinary() {
				ByteArrayOutputStream buffer = new ByteArrayOutputStream();
				ConditionOutputStream stream = new ConditionOutputStream(buffer);
				try {
					stream.writeCondition(this);
					stream.flush();
					return buffer.toByteArray();
				} catch (IOException e) {
					throw new UncheckedIOException(e);
				} finally {
					try {
						stream.close();
					} catch (IOException e) {
						throw new UncheckedIOException(e);
					}
				}
			}
			
			@Override
			public ConditionType getType() {
				return this.getType();
			}
			
			@Override
			public int getMaxFulfillmentLength() {
				//TODO - Does returning the exact length make it too easy to brute force the pre-image?
				return preimage.length;
			}
			
			@Override
			public byte[] getFingerprint() {
				//TODO - Should this be immutable? ArrayCopy?
				return fingerprint;
			}
			
			@Override
			public EnumSet<FeatureSuite> getFeatures() {
				return EnumSet.of(FeatureSuite.PREIMAGE, FeatureSuite.SHA_256);
			}
		};
	}
}

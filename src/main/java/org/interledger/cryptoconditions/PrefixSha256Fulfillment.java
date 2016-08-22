package org.interledger.cryptoconditions;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.EnumSet;

import org.interledger.cryptoconditions.encoding.ConditionOutputStream;
import org.interledger.cryptoconditions.util.Crypto;

//TODO lots of optimizations possible
public class PrefixSha256Fulfillment implements Fulfillment {
	
	private byte[] prefix;
	private Condition subcondition;
	private Fulfillment subfulfillment;
	
	public PrefixSha256Fulfillment() {
		prefix = new byte[0];
		subcondition = null;
		subfulfillment = null;
	}
	
	public PrefixSha256Fulfillment(byte[] prefix, Condition subcondition) {
		setPrefix(prefix);
		setSubCondition(subcondition);
	}

	public PrefixSha256Fulfillment(byte[] prefix, Fulfillment subfulfillment) {
		setPrefix(prefix);
		setSubFulfillment(subfulfillment);
	}

	public void setPrefix(byte[] prefix)
	{
		//TODO - Should this be immutable? Use ArrayCopy?
		this.prefix = prefix;
	}
	
	public byte[] getPrefix() {
		//TODO - Should this object be immutable? Use ArrayCopy?
		return prefix;
	}
	
	public void setSubCondition(Condition condition)
	{
		this.subcondition = condition;
	}
	
	public Condition getSubCondition()
	{
		return subcondition;
	}
	
	public void setSubFulfillment(Fulfillment fulfillment)
	{
		this.subfulfillment = fulfillment;
		setSubCondition(fulfillment.generateCondition());
	}
	
	public Fulfillment getSubFulfillment()
	{
		return subfulfillment;
	}
	
	@Override
	public ConditionType getTypeID() {
		return ConditionType.PREFIX_SHA256;
	}

	@Override
	public byte[] getPayload() {
		//TODO concat varlen(prefix) and condition fingerprint
		return null;
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
		final byte[] fingerprint = Crypto.getSha256Hash(this.prefix);
		
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
				//TODO calculate
				return 0;
			}
			
			@Override
			public byte[] getFingerprint() {
				//TODO - Should this be immutable? ArrayCopy?
				return fingerprint;
			}
			
			@Override
			public EnumSet<FeatureSuite> getFeatures() {
				return EnumSet.of(FeatureSuite.PREFIX, FeatureSuite.SHA_256);
			}
		};
	}

}

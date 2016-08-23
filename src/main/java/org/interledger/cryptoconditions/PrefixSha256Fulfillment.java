package org.interledger.cryptoconditions;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.EnumSet;

import org.interledger.cryptoconditions.encoding.ConditionOutputStream;
import org.interledger.cryptoconditions.encoding.FulfillmentOutputStream;
import org.interledger.cryptoconditions.util.Crypto;

/**
 * Implementation of a PREFIX-SHA-256 crypto-condition fulfillment
 * 
 * TODO Safe synchronized access to members?
 * 
 * @author adrianhopebailie
 *
 */
public class PrefixSha256Fulfillment implements Fulfillment<PrefixSha256Condition> {
	
	private byte[] prefix;
	private Fulfillment<?> subfulfillment;

	private byte[] payload;
	
	public PrefixSha256Fulfillment() {
		prefix = new byte[0];
		payload = null;
		subfulfillment = null;
	}
	
	public PrefixSha256Fulfillment(byte[] prefix, Fulfillment<?> subfulfillment) {
		setPrefix(prefix);
		setSubFulfillment(subfulfillment);
	}

	public void setPrefix(byte[] prefix)
	{
		//TODO - Should this be immutable? Use ArrayCopy?
		this.prefix = prefix;
		this.payload = null;
	}
	
	public byte[] getPrefix() {
		//TODO - Should this object be immutable? Use ArrayCopy?
		return prefix;
	}
			
	public void setSubFulfillment(Fulfillment<?> fulfillment)
	{
		this.subfulfillment = fulfillment;
		this.payload = null;
	}
	
	public Fulfillment<?> getSubFulfillment()
	{
		return subfulfillment;
	}
	
	@Override
	public ConditionType getType() {
		return ConditionType.PREFIX_SHA256;
	}

	@Override
	public byte[] getPayload() {
		if(payload == null) {
			payload = calculatePayload();
		}	
		return payload;
	}

	@Override
	public PrefixSha256Condition generateCondition() {
		
		Condition subcondition = subfulfillment.generateCondition();
		
		EnumSet<FeatureSuite> features = subcondition.getFeatures();
		
		byte[] fingerprint = Crypto.getSha256Hash(
				calculateFingerPrintContent(
					prefix, 
					subcondition
				)
			);
		
		int maxFulfillmentLength = calculateMaxFulfillmentLength(
				prefix, 
				subcondition
			);
		
		return new PrefixSha256Condition(fingerprint, features, maxFulfillmentLength);
	}

	private byte[] calculatePayload()
	{
		
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		FulfillmentOutputStream stream = new FulfillmentOutputStream(buffer);
		
		try {
			stream.writeOctetString(prefix);
			stream.writeFulfillment(subfulfillment);
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

	private byte[] calculateFingerPrintContent(byte[] prefix, Condition subcondition)
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
	
	private int calculateMaxFulfillmentLength(byte[] prefix, Condition subcondition)
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

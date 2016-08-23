package org.interledger.cryptoconditions;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.interledger.cryptoconditions.encoding.FulfillmentOutputStream;

/**
 * Implementation of a PREFIX-SHA-256 crypto-condition fulfillment
 * 
 * TODO Safe synchronized access to members?
 * 
 * @author adrianhopebailie
 *
 */
public class PrefixSha256Fulfillment implements Fulfillment {
	
	private byte[] prefix;
	private Fulfillment subfulfillment;

	private byte[] payload;
	
	public PrefixSha256Fulfillment() {
		prefix = new byte[0];
		payload = null;
		subfulfillment = null;
	}
	
	public PrefixSha256Fulfillment(byte[] prefix, Fulfillment subfulfillment) {
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
			
	public void setSubFulfillment(Fulfillment fulfillment)
	{
		this.subfulfillment = fulfillment;
		this.payload = null;
	}
	
	public Fulfillment getSubFulfillment()
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

}

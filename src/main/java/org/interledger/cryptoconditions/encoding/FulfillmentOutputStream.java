package org.interledger.cryptoconditions.encoding;

import java.io.IOException;
import java.io.OutputStream;

import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.Fulfillment;

/**
 * Writes an OER encoded fulfillment to a stream.
 * 
 * Limitations:
 * - Only supports the compiled condition type codes (up to 4)
 * - Assumes payload length of less than 16777215 bytes
 * 
 * @author adrianhopebailie
 */
public class FulfillmentOutputStream extends OerOutputStream {
			
	public FulfillmentOutputStream(OutputStream stream)
	{
		super(stream);
	}
	
	/**
	 * Write the fulfillment to the underlying stream using OER encoding
	 * per the specification:
	 * 
	 * Fulfillment ::= SEQUENCE {
	 *     type ConditionType,
	 *     payload OCTET STRING
	 * }
	 * 
	 * ConditionType ::= INTEGER {
	 *     preimageSha256(0),
	 *     rsaSha256(1),
	 *     prefixSha256(2),
	 *     thresholdSha256(3),
	 *     ed25519(4)
	 * } (0..65535)
	 * 
	 * @param fulfillment
	 * @throws IOException
	 */
	public void writeFulfillment(Fulfillment fulfillment) throws IOException
	{
		writeConditionType(fulfillment.getType());
		writePayload(fulfillment.getPayload().payload);
		
	}

	protected void writeConditionType(ConditionType type) 
			throws IOException
	{
		write16BitUInt(type.getTypeCode());
	}
	

	protected void writePayload(byte[] payload) 
			throws IOException {
		writeOctetString(payload);			
	}	
}

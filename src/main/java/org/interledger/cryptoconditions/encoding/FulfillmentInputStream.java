package org.interledger.cryptoconditions.encoding;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.Fulfillment;
import org.interledger.cryptoconditions.PrefixSha256Fulfillment;
import org.interledger.cryptoconditions.PreimageSha256Fulfillment;
import org.interledger.cryptoconditions.UnsupportedConditionException;
import org.interledger.cryptoconditions.UnsupportedLengthException;

/**
 * Reads and decodes Fulfillments from an underlying input stream.
 * 
 * Fulfillments are expected to be OER encoded on the stream
 * 
 * @see Fulfillment
 * @author adrianhopebailie
 *
 */
public class FulfillmentInputStream extends OerInputStream {
	
	public FulfillmentInputStream(InputStream stream) {
		super(stream);
	}
	
	/**
	 * Read a fulfillment from the underlying stream using OER encoding
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
	 * @throws IOException
	 * @throws OerDecodingException
	 * @throws UnsupportedConditionException
	 */
	public Fulfillment readFulfillment()
	        throws IOException, UnsupportedConditionException, OerDecodingException 
	{
		final ConditionType type = readConditiontype();
		final byte[] payload = readFingerprint();
		
		switch (type) {
		case PREIMAGE_SHA256:
			return new PreimageSha256Fulfillment(payload);
		case PREFIX_SHA256:
			ByteArrayInputStream byteStream = new ByteArrayInputStream(payload);
			FulfillmentInputStream innerStream = new FulfillmentInputStream(byteStream);
			byte[] prefix = innerStream.readOctetString();
			Fulfillment subfulfillment = innerStream.readFulfillment();
			return new PrefixSha256Fulfillment(prefix, subfulfillment);
		case RSA_SHA256:
			//TODO Implement
		case ED25519:
			//TODO Implement
		case THRESHOLD_SHA256:
			//TODO Implement
		default:
			throw new RuntimeException("Unimplemented fulfillment type encountered.");
		}
		
	}
	
	protected ConditionType readConditiontype() 
			throws IOException {
		int value = read16BitUInt();
		return ConditionType.valueOf(value);
	}


	protected byte[] readFingerprint() 
			throws IOException, UnsupportedLengthException, IllegalLengthIndicatorException {
		
		return readOctetString();
	}

}

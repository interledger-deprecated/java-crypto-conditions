package org.interledger.cryptoconditions.encoding;

import java.io.IOException;
import java.io.OutputStream;
import java.util.EnumSet;

import org.interledger.cryptoconditions.Condition;
import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.FeatureSuite;

/**
 * Writes an OER encoded condition to a stream.
 * 
 * Limitations:
 * - Only supports the compiled condition type codes (up to 4)
 * - Only supports a feature bitmask of 1 byte in length
 * - Assumes fingerprint length of less than 128 bytes
 * - Only accepts a MaxFullfilmentLength of Integer.MAX_VALUE or less
 */
public class ConditionOutputStream extends OutputStream {
	
	private static int SUPPORTED_BITMASK_LENGTH;
	
	static {
		//How many bytes are needed for the supported features bit mask
		SUPPORTED_BITMASK_LENGTH = (FeatureSuite.values().length / 8) + 1;
	}
		
	private final OutputStream stream;
	
	public ConditionOutputStream(OutputStream stream)
	{
		this.stream = stream;
	}
	
	/**
	 * Write the condition to the underlying stream using OER encoding
	 * per the specification:
	 * 
	 * Condition ::= SEQUENCE {
	 *     type ConditionType,
	 *     featureBitmask OCTET STRING,
	 *     fingerprint OCTET STRING,
	 *     maxFulfillmentLength INTEGER (0..MAX)
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
	 * @param condition
	 * @throws IOException
	 */
	public void writeCondition(Condition condition) throws IOException
	{
		writeConditionType(condition.getType());
		writeFeatures(condition.getFeatures());
		writeFingerprint(condition.getFingerprint());
		writeMaxFulfillmentLength(condition.getMaxFulfillmentLength());
		
	}

	protected void writeConditionType(ConditionType type) 
			throws IOException
	{
		//We know there are only 4 types so this will never be more than 255
		// OER encoding says we must use two bytes though because the upper
		// bound is 65535
		stream.write(0);
		stream.write(type.getTypeCode());
	}
	

	protected void writeFeatures(EnumSet<FeatureSuite> features) 
			throws IOException {
		
		//TODO - This is easy to read but could probably optimized
		int encoded_bitmask = 0;
		for (FeatureSuite featureSuite : features) {
			encoded_bitmask += featureSuite.toInt();
		}
		
		writeLengthIndicator(SUPPORTED_BITMASK_LENGTH);
		stream.write(encoded_bitmask);
		
	}
	
	protected void writeFingerprint(byte[] fingerprint) 
			throws IOException {
		writeLengthIndicator(fingerprint.length);		
		stream.write(fingerprint);
			
	}

	private void writeLengthIndicator(int length) throws IOException {
		
		if(length < 128)
		{
			stream.write(length);
		}
		else if(length <= 255) {
			//Write length of length byte "1000 0001"
			stream.write(128 + 1);
			stream.write(length);
		} else if (length <= 65535) {
			//Write length of length byte "1000 0010"
			stream.write(128 + 2);
			stream.write((length >> 8));
			stream.write(length);
		} else {
			//Write length of length byte "1000 0011"
			stream.write(128 + 3);
			stream.write((length >> 16));
			stream.write((length >> 8));
			stream.write(length);
		}
	}

	protected void writeMaxFulfillmentLength(int maxFulfillmentLength) 
			throws IOException {
		
		//We only support a max fulfillment length of Integer.MAX_VALUE
		//But the encoding rules define it as MAXVALUE so we must use a length indicator
		
		if(maxFulfillmentLength <= 255) {
			stream.write(1);
			stream.write(maxFulfillmentLength);
		} else if (maxFulfillmentLength <= 65535) {
			stream.write(2);
			stream.write((maxFulfillmentLength >> 8));
			stream.write(maxFulfillmentLength);
		} else {
			stream.write(3);
			stream.write((maxFulfillmentLength >> 16));
			stream.write((maxFulfillmentLength >> 8));
			stream.write(maxFulfillmentLength);
		}		
	}
	
	
	@Override
	public void write(int b) throws IOException {
		stream.write(b);
	}
	
	 /**
     * Flushes the stream. This will write any buffered output bytes and flush
     * through to the underlying stream.
     *
     * @throws  IOException If an I/O error has occurred.
     */
    public void flush() throws IOException {
    	stream.flush();
    }

    /**
     * Closes the stream. This method must be called to release any resources
     * associated with the stream.
     *
     * @throws  IOException If an I/O error has occurred.
     */
    public void close() throws IOException {
        flush();
        stream.close();
    }
	
}

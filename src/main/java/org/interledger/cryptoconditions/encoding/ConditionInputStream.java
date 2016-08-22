package org.interledger.cryptoconditions.encoding;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URI;
import java.util.EnumSet;

import org.interledger.cryptoconditions.Condition;
import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.FeatureSuite;
import org.interledger.cryptoconditions.UnsupportedConditionException;
import org.interledger.cryptoconditions.UnsupportedFeaturesException;
import org.interledger.cryptoconditions.UnsupportedLengthException;
import org.interledger.cryptoconditions.UnsupportedMaxFullfilmentValueException;

public class ConditionInputStream extends InputStream {
	
	protected final InputStream stream;
	
	public ConditionInputStream(InputStream stream) {
		this.stream = stream;
	}
	
	/**
	 * Read a condition from the underlying stream using OER encoding
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
	 * @throws IOException
	 * @throws DecodingException
	 * @throws UnsupportedConditionException
	 */
	public Condition readCondition()
	        throws IOException, UnsupportedConditionException, DecodingException 
	{
		final ConditionType type = readConditiontype();
		final EnumSet<FeatureSuite> features = readFeatures();
		final byte[] fingerprint = readFingerprint();
		final int maxFulfillmentValue = readMaxFullfilmentValue();		
		
		return new Condition() {
			
			@Override
			public String toString() {
				// TODO Use writer
				return null;
			}
			
			@Override
			public byte[] toBinary() {
				
				//TODO: We could optimize this by writing to the buffer as we read from the underlying
				// stream but this has some synchronization considerations it also adds over-head to 
				// the read operations which may be unnecessary
				
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
				return type;
			}
			
			@Override
			public int getMaxFulfillmentLength() {
				return maxFulfillmentValue;
			}
			
			@Override
			public byte[] getFingerprint() {
				return fingerprint;
			}
			
			@Override
			public EnumSet<FeatureSuite> getFeatures() {
				return features;
			}
		};
	}
	
	protected ConditionType readConditiontype() 
			throws IOException {
		int value = stream.read();
		verifyNotEOF(value);
		return ConditionType.valueOf(value);
	}

	protected EnumSet<FeatureSuite> readFeatures() 
			throws IOException, UnsupportedFeaturesException, UnsupportedLengthException, IllegalLengthIndicatorException {
		
		int length = readLengthIndicator();
		
		//We currently only support a bitmask of 1 byte
		if(length == 1)
		{
			int bitMask = stream.read();
			verifyNotEOF(bitMask);
			EnumSet<FeatureSuite> features = EnumSet.noneOf(FeatureSuite.class);
			for (FeatureSuite featureSuite : FeatureSuite.values()) {
				if((featureSuite.toInt() & bitMask) == featureSuite.toInt())
				{
					features.add(featureSuite);
				}
			}
		} else {
			//We currently only support a bitmask of 1 byte
			throw new UnsupportedFeaturesException("Unknown feature bits encountered.");
		}
		
		return null;
	}

	protected byte[] readFingerprint() 
			throws IOException, UnsupportedLengthException, IllegalLengthIndicatorException {
		int length = readLengthIndicator();
		
		byte[] buffer = new byte[length];
		int bytesRead = stream.read(buffer, 0, length);
		
		if(bytesRead < length) {
			throw new EOFException("Unexpected EOF.");
		}
		
		return buffer;
	}
	
	private int readMaxFullfilmentValue() 
			throws UnsupportedMaxFullfilmentValueException, IOException, UnsupportedLengthException, IllegalLengthIndicatorException {
		int length = readLengthIndicator();
		
		if(length > 3) {
			throw new UnsupportedMaxFullfilmentValueException("This implementation only supports "
					+ "maximum fullfilment values up to " + Integer.toString(Integer.MAX_VALUE) + ".");
		}
		
		int maxFullfilmentValue = 0;
		
		for (int i = 1; i <= length; i++) {
			int next = stream.read();
			verifyNotEOF(next);
			length += (next << (8 * (length - i)));
		}
		
		return maxFullfilmentValue;
	}

	@Override
	public int read() throws IOException {
		return stream.read();
	}
	
	private int readLengthIndicator() 
			throws IOException, UnsupportedLengthException, IllegalLengthIndicatorException {
		int length = stream.read();
		verifyNotEOF(length);
		
		if(length < 128) {
			return length;
		}		
		else if(length > 128)
		{
			int lengthOfLength = length - 127;
			if(lengthOfLength > 3) {
				throw new UnsupportedLengthException("This implementation only supports "
						+ "variable length fields up to " + Integer.toString(Integer.MAX_VALUE) + "bytes.");
			}
			
			length = 0;
			for (int i = 1; i <= lengthOfLength; i++) {
				int next = stream.read();
				verifyNotEOF(next);
				length += (next << (8 * (length - i)));
			}
			return length;
		} else {
			throw new IllegalLengthIndicatorException("First byte of length indicator can't be 0x80.");	
		}
	}
	
	private void verifyNotEOF(int data) throws EOFException {
		if(data == -1){
			throw new EOFException("Unexpected EOF when trying to decode condition.");
		}
	}

}

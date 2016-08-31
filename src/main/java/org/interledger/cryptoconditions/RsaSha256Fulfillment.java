package org.interledger.cryptoconditions;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.spec.RSAPublicKeySpec;
import java.util.EnumSet;

import org.interledger.cryptoconditions.encoding.FulfillmentOutputStream;
import org.interledger.cryptoconditions.util.Crypto;

/**
 * Implementation of a PREIMAGE-SHA-256 crypto-condition fulfillment
 * 
 * TODO Safe synchronized access to members?
 * 
 * @author adrianhopebailie
 *
 */
public class RsaSha256Fulfillment implements Fulfillment {

	private static ConditionType CONDITION_TYPE = ConditionType.RSA_SHA256;	
	private static EnumSet<FeatureSuite> BASE_FEATURES = EnumSet.of(
			FeatureSuite.SHA_256, 
			FeatureSuite.RSA_PSS
		);
	private static BigInteger RSA_PUBLIC_EXPONENT = BigInteger.valueOf(65537);
	private static int MINIMUM_MODULUS_SIZE = 128;
	private static int MAXIMUM_MODULUS_SIZE = 512;

	private byte[] modulus;
	private byte[] signature;
	
	private byte[] payload;
			
	public RsaSha256Fulfillment(byte[] modulus, byte[] signature) {
		setModulus(modulus);
		setSignature(signature);
	}

	public void setModulus(byte[] modulus)
	{
		if(modulus.length < MINIMUM_MODULUS_SIZE)
			throw new IllegalArgumentException("Modulus must be more than " + 
					Integer.toString(MINIMUM_MODULUS_SIZE) + " bytes.");
		
		if(modulus.length > MAXIMUM_MODULUS_SIZE)
			throw new IllegalArgumentException("Modulus must be less than " + 
					Integer.toString(MAXIMUM_MODULUS_SIZE) + " bytes.");
		
		this.modulus = modulus;
	}
	
	public byte[] getModulus() {
		//TODO - Should this object be immutable? Return a copy?
		return modulus;
	}
	
	public void setSignature(byte[] signature)
	{
		if(modulus.length != signature.length)
			throw new IllegalArgumentException("Modulus and signature must be the same size.");

		if(new BigInteger(modulus).compareTo(new BigInteger(signature)) < 0)
			throw new IllegalArgumentException("Modulus must be larger, numerically, than signature.");
		
		this.signature = signature;
	}
	
	public byte[] getSignature() {
		//TODO - Should this object be immutable? Return a copy?
		return signature;
	}
		
	public RSAPublicKeySpec getKey() {
		//TODO - Should this object be immutable? Return a copy?
		return new RSAPublicKeySpec(new BigInteger(modulus), RSA_PUBLIC_EXPONENT);
	}
	
	@Override
	public ConditionType getType() {
		return ConditionType.PREIMAGE_SHA256;
	}

	@Override
	public byte[] getPayload() {
		if(payload == null) {
			payload = calculatePayload();
		}	
		return payload;
	}

	@Override
	public Condition generateCondition() {
		byte[] fingerprint = Crypto.getSha256Hash(modulus);
		int maxFulfillmentLength = modulus.length;
	
		return new ConditionImpl(
				CONDITION_TYPE, 
				BASE_FEATURES, 
				fingerprint, 
				maxFulfillmentLength);
	}
	
	private byte[] calculatePayload()
	{
		
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		FulfillmentOutputStream stream = new FulfillmentOutputStream(buffer);
		
		try {
			stream.writeOctetString(modulus);
			stream.writeOctetString(signature);
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

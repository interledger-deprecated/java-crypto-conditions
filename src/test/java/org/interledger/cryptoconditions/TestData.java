package org.interledger.cryptoconditions;

public class TestData {
	
	public static final byte[] PreimageSha256Condition0x00 = new byte[]{
			0x00, 0x00, //Type = PREIMAGE SHA256
			0x01, 0x03, //Features = SHA256 and PREIMAGE
			0x01, 0x00, //Fingerprint = 0x00
			0x01, 0x01, //Max fulfillment = 1
	};	
	
	public static final byte[] PreimageSha256Condition0xFF = new byte[]{
			0x00, 0x00, //Type = PREIMAGE SHA256
			0x01, 0x03, //Features = SHA256 and PREIMAGE
			0x01, (byte) 0xFF, //Fingerprint = 0x00
			0x01, 0x01, //Max fulfillment = 1
	};	
	
}

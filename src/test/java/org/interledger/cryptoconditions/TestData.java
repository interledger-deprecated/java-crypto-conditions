package org.interledger.cryptoconditions;

import java.util.Arrays;

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
	
	public static final byte[] All0x00ByteArrayLength1 = new byte[1];
	public static final byte[] All0x00ByteArrayLength8 = new byte[8];
	public static final byte[] All0x00ByteArrayLength16 = new byte[16];
	public static final byte[] All0x00ByteArrayLength256 = new byte[256];

	public static final byte[] All0xFFByteArrayLength1 = new byte[1];
	public static final byte[] All0xFFByteArrayLength8 = new byte[8];
	public static final byte[] All0xFFByteArrayLength16 = new byte[16];
	public static final byte[] All0xFFByteArrayLength256 = new byte[256];

	
	static
	{
		Arrays.fill(All0x00ByteArrayLength1,(byte) 0x00);
		Arrays.fill(All0x00ByteArrayLength8,(byte) 0x00);
		Arrays.fill(All0x00ByteArrayLength16,(byte) 0x00);
		Arrays.fill(All0x00ByteArrayLength256,(byte) 0x00);
		
		Arrays.fill(All0xFFByteArrayLength1,(byte) 0xFF);
		Arrays.fill(All0xFFByteArrayLength8,(byte) 0xFF);
		Arrays.fill(All0xFFByteArrayLength16,(byte) 0xFF);
		Arrays.fill(All0xFFByteArrayLength256,(byte) 0xFF);

	}
	
	
}

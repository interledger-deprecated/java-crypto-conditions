package org.interledger.cryptoconditions;

public enum FeatureSuite {
	
	SHA_256(1),
	PREIMAGE(2),
	PREFIX(4),
	THRESHOLD(8),
	RSA_PSS(16),
	ED25519(32);
	
	private final int byteValue;
		
	FeatureSuite(int byteValue){
		this.byteValue = byteValue;
	}
	
	//TODO This only works while we only need a single byte
	public int toInt() {
		return this.byteValue;
	}
}

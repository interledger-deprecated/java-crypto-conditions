package org.interledger.cryptoconditions;

import java.util.EnumSet;

/**
 * Enumeration of crypto-condition features
 * 
 * @author adrianhopebailie
 */
public enum FeatureSuite {
	
	SHA_256   (1<<0),
	PREIMAGE  (1<<1),
	PREFIX    (1<<2),
	THRESHOLD (1<<3),
	RSA_PSS   (1<<4),
	ED25519   (1<<5);
	
	private static final short mostSignificantBit = 5;
	private static final int maxByteValue = (2<<(mostSignificantBit)) - 1; 
	private final short byteValue;
		
	FeatureSuite(int byteValue){
		if ( byteValue > maxByteValue ) throw new 
			RuntimeException("Feature Suite not supported");
		this.byteValue = (short) byteValue;
	}
	
	//TODO This only works while we only need a single byte
	public int toInt() {
		return this.byteValue;
	}
	
	public static EnumSet<FeatureSuite> bitMask2EnumSet(int bitMask){
		EnumSet<FeatureSuite> result = EnumSet.noneOf(FeatureSuite.class);
		if ((bitMask & 1<<0) != 0) result.add(FeatureSuite.SHA_256  );
		if ((bitMask & 1<<1) != 0) result.add(FeatureSuite.PREIMAGE );
		if ((bitMask & 1<<2) != 0) result.add(FeatureSuite.PREFIX   );
		if ((bitMask & 1<<3) != 0) result.add(FeatureSuite.THRESHOLD);
		if ((bitMask & 1<<4) != 0) result.add(FeatureSuite.RSA_PSS  );
		if ((bitMask & 1<<5) != 0) result.add(FeatureSuite.ED25519  );
		return result;
	}
	
	public static int EnumSet2bitMask(EnumSet<FeatureSuite> featureSet){
		int result = 0;
		for (FeatureSuite feature : featureSet){
			switch (feature){
				case SHA_256  : result = result | SHA_256  .toInt(); break;
				case PREIMAGE : result = result | PREIMAGE .toInt(); break;
				case PREFIX   : result = result | PREFIX   .toInt(); break;
				case THRESHOLD: result = result | THRESHOLD.toInt(); break;
				case RSA_PSS  : result = result | RSA_PSS  .toInt(); break;
				case ED25519  : result = result | ED25519  .toInt(); break;
			}
		}
		return result;
	}
}

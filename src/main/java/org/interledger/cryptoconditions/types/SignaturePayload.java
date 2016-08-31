package org.interledger.cryptoconditions.types;

/*
 * wrapper arround byte[] to provide type safety.
 * 
 * Used to genereate public/private keys.
 */
public class SignaturePayload {
	public final byte[] payload;
	public SignaturePayload(byte[] source){
		this.payload = source.clone();
	}
}

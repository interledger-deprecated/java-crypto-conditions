package org.interledger.cryptoconditions.types;

/*
 * wrapper arround byte[] to provide type safety.
 * 
 * Used to genereate public/private keys.
 */
public class KeyPayload {
    public final byte[] payload;
    public KeyPayload(byte[] source){
        this.payload = source.clone();
    }
}

package org.interledger.cryptoconditions.types;

/*
 * wrapper arround byte[] to provide type safety.
 * 
 * Used to genereate public/private keys.
 */
public class FulfillmentPayload {
    public final byte[] payload;
    public FulfillmentPayload(byte[] source){
        this.payload = source.clone();
    }
}

package org.interledger.cryptoconditions.types;

/*
 * wrapper arround byte[] to provide type safety.
 * 
 * Used to genereate public/private keys.
 */
public class MessagePayload {

    public final byte[] payload;

    public MessagePayload(byte[] source) {
        this.payload = source.clone();
    }
}

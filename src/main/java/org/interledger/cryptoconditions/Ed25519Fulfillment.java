package org.interledger.cryptoconditions;

import java.util.Arrays;
import java.util.EnumSet;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
//import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.PrivateKey;

import java.security.Signature;



import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.EdDSAEngine;
// TODO:(0) Add dependencies in ed25519 external library.
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

import org.interledger.cryptoconditions.types.*;
/**
 * Implementation of a PREFIX-SHA-512 crypto-condition fulfillment
 * 
 * TODO Safe synchronized access to members?
 * 
 * @author earizon<enrique.arizon.benito@everis.com>
 *
 */

public class Ed25519Fulfillment extends FulfillmentBase {
    // TODO:(?) Create utility classes to generate public/private keys
	//     for example for a site that just one a one-time-use public/private key.
    public static final int PUBKEY_LENGTH = 32; 
    public static final int SIGNATURE_LENGTH = 64; 
    public static final int FULFILLMENT_LENGTH = PUBKEY_LENGTH + SIGNATURE_LENGTH;

    private final PublicKey publicKey;
    private SignaturePayload signature;

    private static EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName("ed25519-sha-512");


    private static PublicKey _publicKeyFromByteArray(KeyPayload pub_key)
    {
        EdDSAPublicKeySpec pubKey = new EdDSAPublicKeySpec(pub_key.payload, spec);
        return new EdDSAPublicKey(pubKey);
    }
    
    private static PrivateKey _privateFromByteArray(KeyPayload priv_key)
    {
    	throw new RuntimeException("Not implemented"); // TODO:(0)
    }
    

    /*
     * Returns an initialized instance.
     * 
     * if publicKeySource is null it's generated from the privateKey.
     */
    public static Ed25519Fulfillment BuildFromSecrets(
    		KeyPayload privateKeySource, KeyPayload publicKeySource, MessagePayload message)
    {
        if (java.math.BigDecimal.ONE.equals("")) throw new RuntimeException("Not implemented"); // TODO:(0)

        // const keyPair = ed25519.MakeKeypair(privateKey)
        // this.signature = ed25519.Sign(message, keyPair)
    	PrivateKey privKey = _privateFromByteArray(privateKeySource);

        PublicKey publicKey = null; // TODO:(0)
        if (publicKeySource != null) {
        	publicKey = _publicKeyFromByteArray(publicKeySource);
        } else {
        	// TODO:(0) Precalculate publicKey/publicKeySource from privKey
        	publicKeySource = new KeyPayload(publicKey.getEncoded());
        }
        // Ref: EdDSAEngineTest.java
        // TODO:(0) Check reuse of sgr
        SignaturePayload signature;
        try {
            Signature sgr;
            sgr = new EdDSAEngine(MessageDigest.getInstance("SHA-512"));
            sgr.initSign(privKey);
            sgr.update(message.payload);
            signature = new SignaturePayload(sgr.sign()); // TODO:(0) Check sgr.sign() "invented"
        }catch(Exception e){
        	throw new RuntimeException(e.toString(), e);
        }
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        try {
            buffer.write(publicKeySource.payload);
            buffer.write(signature.payload);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        
        Ed25519Fulfillment result = new 
                Ed25519Fulfillment(ConditionType.ED25519, new FulfillmentPayload(buffer.toByteArray()));
        return result;
    }

    /*
     * public key and signarutes are extracted from the payload
     */
    public Ed25519Fulfillment(ConditionType type, FulfillmentPayload payload) {
        super(type, payload);
        if (payload.payload.length < FULFILLMENT_LENGTH) {
        	throw new RuntimeException("payload.length <"+ FULFILLMENT_LENGTH);
        }
        // TODO:(0) Test implementation correct.
        if (payload.payload.length != FULFILLMENT_LENGTH) throw new
            RuntimeException("payload length ("+payload.payload.length+")"
                + " doesn't match Ed25519 fulfillment length ("+FULFILLMENT_LENGTH+")");
        /*
         * REF: https://interledger.org/five-bells-condition/spec.html#rfc.section.4.5.2
         * Ed25519FulfillmentPayload ::= SEQUENCE {
         *     publicKey OCTET STRING (SIZE(32)),
         *     signature OCTET STRING (SIZE(64))
         * }
         */
        publicKey = _publicKeyFromByteArray(new KeyPayload(
        Arrays.copyOfRange(payload.payload, 0, Ed25519Fulfillment.PUBKEY_LENGTH)) );
        this.signature = new SignaturePayload(
        	Arrays.copyOfRange(payload.payload, Ed25519Fulfillment.PUBKEY_LENGTH, Ed25519Fulfillment.FULFILLMENT_LENGTH));
    }




    @Override
    public ConditionType getType() {
        return ConditionType.ED25519;
    }

    @Override
    public FulfillmentPayload getPayload() 
    {
        return payload;
    }

    @Override
    public Condition generateCondition() 
    {
        if (this.publicKey == null ) {
        	// TODO:(0) This will fail now. generateCondition is called before privateKey is set
            throw new RuntimeException("this.publicKey not yet defined ");
        }
        EnumSet<FeatureSuite> features = EnumSet.of(FeatureSuite.ED25519); // TODO:(0) Recheck

//        PrivateKey sKey = new EdDSAPrivateKey(
//                new EdDSAPrivateKeySpec(
//                        this.privateKey, EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.CURVE_ED25519_SHA512)));
        try {
            return new ConditionImpl(
                    ConditionType.ED25519, 
                    features,
                    this.publicKey.getEncoded(), 
                    FULFILLMENT_LENGTH);
        } catch (Exception e) {
            throw new RuntimeException(e.toString(), e);
        }
    }

    @Override
    public boolean validate(MessagePayload message) {
    	if (this.publicKey == null) {
    		throw new RuntimeException("publicKey not initialized");
    	}
        try{
            Signature sgr = new EdDSAEngine(MessageDigest.getInstance("SHA-512"));
            sgr.initVerify(this.publicKey);
            sgr.update(message.payload);
            return sgr.verify(signature.payload);
    	}catch(Exception e){
    		throw new RuntimeException(e.toString(), e);
    	}
    }
}

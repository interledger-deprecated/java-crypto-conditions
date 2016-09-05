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
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;

import org.interledger.cryptoconditions.types.*;
/**
 * Implementation of a Ed25519 crypto-condition fulfillment
 * 
 * @author earizon<enrique.arizon.benito@everis.com>
 *
 */

public class Ed25519Fulfillment extends FulfillmentBase {
    /*
     *  TODO:(?) Create utility classes to generate public/private keys
     *      for example for a site that just one a one-time-use public/private key.
     */
    
    /*
     * Note: 
     *  The java Ed25519 implementation uses a private Key Seed while some other
     *  implementations use the "expanded private key". 
     *  Extracted from 
     *  http://stackoverflow.com/questions/23092549/interoperability-between-java-and-javascript-ed25519-implementations
     *  
     *  """
     *      Some work with an expanded private key, others ask for both the 
     *      seed and the public key when signing
     *      This difference only applies to the signing function, not 
     *      the verification function.
     *  ...
     *   """
     *   FROM https://blog.mozilla.org/warner/2011/11/29/ed25519-keys/:
     *   private Sheed to Expanded private key:
     *   32-byte(256bits) SHEED -> HASH SHA512 -> 64bytes(512bits) -> split [left(32bytes),right(32bytes)]
     *   left -> "massaged into curve25519 private scalar "a" by setting and clearing a few
     *          high/low-order bits. -> pubkey (32bytes, group element "A") = private scalar "a" * "B"
     *          "B" beeing the generator.
     *   (it’s the multiplications that take the most time: everything else is trivial by comparison)
     */
    
    
    private static boolean userIsAwareOfSecurityIssues = false;
    public static final int PUBKEY_LENGTH = 32; 
    public static final int SIGNATURE_LENGTH = 64; 
    public static final int FULFILLMENT_LENGTH = PUBKEY_LENGTH + SIGNATURE_LENGTH;

    private final PublicKey publicKey;
    private SignaturePayload signature;

    private static EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName("ed25519-sha-512");


    private static PrivateKey _privateKeyFromByteArray(KeyPayload priv_key_sheed)
    {
        EdDSAPrivateKeySpec privKeySpec = new EdDSAPrivateKeySpec(priv_key_sheed.payload, spec);
        return new EdDSAPrivateKey(privKeySpec);
    }

    private static PublicKey _publicKeyFromByteArray(KeyPayload pub_key)
    {
        EdDSAPublicKeySpec pubKey = new EdDSAPublicKeySpec(pub_key.payload, spec);
        return new EdDSAPublicKey(pubKey);
    }

    private static PublicKey _publicKeyFromPrivateKey(EdDSAPrivateKeySpec privKey)
    {
        EdDSAPublicKeySpec pubKeySpec = new EdDSAPublicKeySpec(privKey.getA(), spec);
        return new EdDSAPublicKey(pubKeySpec);
    }

    /*
     * Returns an initialized instance.
     * 
     * if publicKeySource is null it's generated from the privateKey.
     */
    public static Ed25519Fulfillment BuildFromSecrets(
            KeyPayload priv_key_sheed, MessagePayload message)
    {
        if (!Ed25519Fulfillment.userIsAwareOfSecurityIssues) { throwSecurityIssuesWarning(); }

        // TODO:(?) generating the PrivateKey from the key_sheed is "slow". Allow to use a precomputed one?
        EdDSAPrivateKeySpec privKeySpec = new EdDSAPrivateKeySpec(priv_key_sheed.payload, spec);
        PrivateKey privKey = new EdDSAPrivateKey(privKeySpec);
        PublicKey  pubKey = _publicKeyFromPrivateKey(privKeySpec);
        
        // Ref: EdDSAEngineTest.java
        // TODO:(?) Check reuse of sgr
        SignaturePayload signature;
        try {
            Signature sgr;
            sgr = new EdDSAEngine(MessageDigest.getInstance("SHA-512"));
            sgr.initSign(privKey);
            sgr.update(message.payload);
            signature = new SignaturePayload(sgr.sign());
        }catch(Exception e){
            throw new RuntimeException(e.toString(), e);
        }
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] PublicKey32Bytes = ((EdDSAPublicKey)pubKey).getA().toByteArray();

        try {
            buffer.write(PublicKey32Bytes);
            buffer.write(signature.payload);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        byte[] payload = buffer.toByteArray();

        Ed25519Fulfillment result = new 
                Ed25519Fulfillment(ConditionType.ED25519, new FulfillmentPayload(buffer.toByteArray()));
        return result;
    }

    /*
     * public key and signarutes are extracted from the payload
     */
    public Ed25519Fulfillment(ConditionType type, FulfillmentPayload payload) {
        super(type, payload);
        if (!Ed25519Fulfillment.userIsAwareOfSecurityIssues) { throwSecurityIssuesWarning(); }
        if (payload.payload.length < FULFILLMENT_LENGTH) {
            throw new RuntimeException("payload.length <"+ FULFILLMENT_LENGTH);
        }
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
    public Condition generateCondition() 
    {
        if (this.publicKey == null ) {
            throw new RuntimeException("this.publicKey not yet defined ");
        }
        EnumSet<FeatureSuite> features = EnumSet.of(FeatureSuite.ED25519);

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
    
    public static void UserHasReadEd25519JavaDisclaimerAndIsAwareOfSecurityIssues() {
        userIsAwareOfSecurityIssues = true;
    }
    
    private static void throwSecurityIssuesWarning() {
        throw new RuntimeException(
            "\n"
          + "WARN: \n"
          + "  | C&P From https://github.com/str4d/ed25519-java:\n"
          + "  | Disclaimer:\n"
          + "  | There are no guarantees that this is secure for all uses.\n"
          + "  | All unit tests are passing, including tests against the data from the Python implementation,\n"
          + "  | and the code has been reviewed by an independent developer, but it has not yet been audited\n"
          + "  | by a professional cryptographer. In particular, the constant-time signing properties of ref10\n "
          + "  | may not have been completely retained (although this is the eventual goal for the\n"
          + "  | Ed25519-specific implementation).\n"
          + "  |\n"
          + "  | To use Ed25519Fulfillment you must first activate it executing the next code:\n"
          + "  |     Ed25519Fulfillment.UserHasReadEd25519JavaDisclaimerAndIsAwareOfSecurityIssues();"
          + "\n\n\n"
        );
    }
}

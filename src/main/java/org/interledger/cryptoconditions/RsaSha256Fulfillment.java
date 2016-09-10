package org.interledger.cryptoconditions;

import java.math.BigInteger;
//import java.security.spec.PKCS8EncodedKeySpec;

import java.security.spec.X509EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.EnumSet;
import java.util.Enumeration;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPrivateKeySpec;
//import java.security.spec.RSAPublicKeySpec;

import sun.security.util.DerInputStream;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.KeyFactory;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.util.encoders.Base64;
import org.interledger.cryptoconditions.FulfillmentBase;
import org.interledger.cryptoconditions.encoding.ByteArrayOutputStreamPredictor;
import org.interledger.cryptoconditions.encoding.FulfillmentOutputStream;
import org.interledger.cryptoconditions.types.FulfillmentPayload;
import org.interledger.cryptoconditions.types.KeyPayload;
import org.interledger.cryptoconditions.types.MessagePayload;
import org.interledger.cryptoconditions.util.Crypto;


/**
 * Implementation of a PREIMAGE-SHA-256 crypto-condition fulfillment
 *
 * TODO Safe synchronized access to members?
 *
 * @author adrianhopebailie
 *
 */
public class RsaSha256Fulfillment extends FulfillmentBase {

    private static final ConditionType CONDITION_TYPE = ConditionType.RSA_SHA256;
    private static final EnumSet<FeatureSuite> BASE_FEATURES = EnumSet.of(
            FeatureSuite.SHA_256,
            FeatureSuite.RSA_PSS
    );
    private static final BigInteger RSA_PUBLIC_EXPONENT = BigInteger.valueOf(65537);
    private static final int MINIMUM_MODULUS_SIZE = 128;
    private static final int MAXIMUM_MODULUS_SIZE = 512;

    
    private final BigInteger modulus; // Use byte[]
    private final byte[] signature;
    
    private RSAPublicKeySpec publicKey;

    
    private static Signature signatureEngine;
    private static KeyFactory kf; // or "EC" or whatever

    static {
        try {
            signatureEngine = Signature.getInstance("SHA1withRSA"/*, "BC"*/);
        } catch (Exception e) {
            throw new RuntimeException("Couldn't start Signature Engine bouncycastle. \n"
                    + "Check that bcprov*.jar is on your classpath.\n"
                    + "This code was originally compiled against bcprov-jdk15-1.46.jar from the Maven repository available at. \n"
                    + "http://repo2.maven.org/maven2/org/bouncycastle/bcprov-jdk15/1.46/bcprov-jdk15-1.46.jar ");
        }
        try {
            kf = KeyFactory.getInstance("RSA");
        } catch (Exception e) {
            throw new RuntimeException(e.toString(), e);
        }

    }

    public static RsaSha256Fulfillment BuildFromSecrets(String PEMEncodedPrivateKey, byte[] message) {
        ConditionType type = ConditionType.RSA_SHA256;
        
        try {
//            privKey = (RSAPrivateKeySpec)kf.generatePrivate(new PKCS8EncodedKeySpec(privateKey.payload));
            RSAPrivateKeySpec privKeySpec = RsaSha256Fulfillment.parsePEMEncodedPrivateKey(PEMEncodedPrivateKey);
            PrivateKey privKey = kf.generatePrivate(privKeySpec);
            signatureEngine.initSign(privKey, new SecureRandom());
            BigInteger modulus = privKeySpec.getModulus();
            signatureEngine.update(message);
            byte[] signature =  signatureEngine.sign();
    
            FulfillmentPayload payload = RsaSha256Fulfillment.calculatePayload(modulus, signature);
    
            return new RsaSha256Fulfillment(type, payload, modulus, signature);
        } catch (Exception e) {
            throw new RuntimeException(e.toString(), e);
        }
    }

    private RsaSha256Fulfillment(ConditionType type, FulfillmentPayload payload, BigInteger modulus, byte[] signature) {
        super(type, payload);
        // TODO: CHECK toString(10) fails with test-data
        if (modulus.toString(16).length() < MINIMUM_MODULUS_SIZE ) {
            throw new RuntimeException("Modulus must be more than "
                    + Integer.toString(MINIMUM_MODULUS_SIZE) + " bytes.");
        }

        if (modulus.toString(16).length() > MAXIMUM_MODULUS_SIZE ) {
            throw new RuntimeException("Modulus must be less than "
                    + Integer.toString(MAXIMUM_MODULUS_SIZE) + " bytes.");
        }

        // TODO: FIXME
//        if (modulus.length != signature.length) {
//            throw new RuntimeException("Modulus and signature must be the same size.");
//        }

        if (modulus.compareTo(new BigInteger(signature)) < 0) { // TODO: > or >=
            throw new RuntimeException("Modulus must be larger, numerically, than signature.");
        }

        
        this.modulus = modulus;
        this.signature = signature.clone();
    }

    public BigInteger getModulus() { return modulus; }

    public byte[] getSignature() { return signature.clone(); }

    private RSAPublicKeySpec getPublicKey() {
        if (this.publicKey != null ) { return this.publicKey; }
        this.publicKey = new RSAPublicKeySpec(modulus, RSA_PUBLIC_EXPONENT);
        return this.publicKey;
    }

    @Override
    public ConditionType getType() {
        return ConditionType.RSA_SHA256;
    }

    private int calculateMaxFulfillmentLength() {
        // Calculate resulting total maximum fulfillment size
        ByteArrayOutputStreamPredictor buffer = new ByteArrayOutputStreamPredictor();
        FulfillmentOutputStream ffos = new FulfillmentOutputStream(buffer);
        try {
            ffos.writeOctetString(this.modulus.toByteArray()); // TODO: FIXME. Recheck. Twice the modulus??
            ffos.writeOctetString(this.modulus.toByteArray());
            int result = buffer.size();
            return result;
        } catch(Exception e) {
            throw new RuntimeException(e.toString(), e);
        } finally {
            ffos.close(); 
        }
    }
    
    @Override
    public Condition generateCondition() {
        byte[] fingerprint = Crypto.getSha256Hash(modulus.toByteArray());
        int maxFulfillmentLength = this.calculateMaxFulfillmentLength();

        return new ConditionImpl(
                CONDITION_TYPE,
                BASE_FEATURES,
                fingerprint,
                maxFulfillmentLength);
    }

    private static FulfillmentPayload calculatePayload(BigInteger modulus, byte[] signature) {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        FulfillmentOutputStream stream = new FulfillmentOutputStream(buffer);
        try {
            stream.writeOctetString(modulus.toByteArray());
            stream.writeOctetString(signature);
            return new FulfillmentPayload(buffer.toByteArray());
        } catch (IOException e) {
            throw new RuntimeException(e);
        } finally {
            stream.close();
        }
    }

    @Override
    public boolean validate(MessagePayload message) {
        try {
            signatureEngine.initVerify((PublicKey)this.getPublicKey());
            signatureEngine.update(message.payload);
            // System.out.println(signatureEngine.verify(this.signature));
            return signatureEngine.verify(this.signature);

        } catch (Exception e) {
            throw new RuntimeException(e.toString(), e);
        }
    }

    private static RSAPrivateKeySpec parsePEMEncodedPrivateKey(String privKey) {
        // REF:stackoverflow.com/questions/7216969/getting-rsa-private-key-from-pem-base64-encoded-private-key-file        
        String privKeyPEM = privKey
            .replace("-----BEGIN RSA PRIVATE KEY-----\n", "")
            .replace("-----END RSA PRIVATE KEY-----"    , "");
        
        // Base64 decode the data
        
        byte[] encodedPrivateKey = Base64.decode(privKeyPEM);
        
        try {
            ASN1Sequence primitive = (ASN1Sequence) ASN1Sequence
                .fromByteArray(encodedPrivateKey);
            Enumeration<?> e = primitive.getObjects();
            BigInteger v = ((DERInteger) e.nextElement()).getValue();
        
            int version = v.intValue();

            if (version != 0 && version != 1) {
                throw new IllegalArgumentException("wrong version for RSA private key");
            }
            /**
             * In fact only modulus and private exponent are in use.
             */
            BigInteger modulus = ((DERInteger) e.nextElement()).getValue();
            BigInteger publicExponent = ((DERInteger) e.nextElement()).getValue();
            BigInteger privateExponent = ((DERInteger) e.nextElement()).getValue();
//            BigInteger prime1 = ((DERInteger) e.nextElement()).getValue();
//            BigInteger prime2 = ((DERInteger) e.nextElement()).getValue();
//            BigInteger exponent1 = ((DERInteger) e.nextElement()).getValue();
//            BigInteger exponent2 = ((DERInteger) e.nextElement()).getValue();
//            BigInteger coefficient = ((DERInteger) e.nextElement()).getValue();
        
            RSAPrivateKeySpec spec = new RSAPrivateKeySpec(modulus, privateExponent);
            return spec;

        } catch (Exception e) {
            throw new RuntimeException(e.toString(),e);
        }
    }

}

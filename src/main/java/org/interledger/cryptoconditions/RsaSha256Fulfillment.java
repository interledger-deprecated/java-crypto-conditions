package org.interledger.cryptoconditions;

import java.math.BigInteger;

import java.util.EnumSet;
import java.util.Enumeration;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.util.encoders.Base64;

import org.interledger.cryptoconditions.FulfillmentBase;
import org.interledger.cryptoconditions.encoding.ByteArrayOutputStreamPredictor;
import org.interledger.cryptoconditions.encoding.FulfillmentOutputStream;
import org.interledger.cryptoconditions.types.FulfillmentPayload;
import org.interledger.cryptoconditions.types.MessagePayload;
import org.interledger.cryptoconditions.types.SignaturePayload;
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

    
    private static KeyFactory kf; // or "EC" or whatever
    // http://fossies.org/linux/envelopes-sourceonly/thirdparty/bouncycastle-135-customized/test/src/org/bouncycastle/jce/provider/test/PSSTest.java
    
    static {
        Security.addProvider(new BouncyCastleProvider());
        try {
            kf = KeyFactory.getInstance("RSA", "BC");
        } catch (Exception e) {
            throw new RuntimeException(e.toString(), e);
        }
    }

    private static Signature getSignEngine(){
        try {
            // TODO: CHECK Can initialize once and make static?
            Signature result = Signature.getInstance("SHA256withRSA/PSS", "BC"); //  SHA256withRSA
            return result;
        } catch (Exception e) {
            throw new RuntimeException("Couldn't start Signature Engine bouncycastle. \n"
                    + "Check that bcprov*.jar is on your classpath.\n"
                    + "This code was originally compiled against bcprov-jdk15-1.46.jar from the Maven repository available at. \n"
                    + "http://repo2.maven.org/maven2/org/bouncycastle/bcprov-jdk15/1.46/bcprov-jdk15-1.46.jar ");
        }

    }

    public static RsaSha256Fulfillment BuildFromSecrets(String PEMEncodedPrivateKey, byte[] message, SecureRandom saltRandom) {
        ConditionType type = ConditionType.RSA_SHA256;
        
        try {
//            privKey = (RSAPrivateKeySpec)kf.generatePrivate(new PKCS8EncodedKeySpec(privateKey.payload));
            RSAPrivateKeySpec privKeySpec = RsaSha256Fulfillment.parsePEMEncodedPrivateKey(PEMEncodedPrivateKey);
            PrivateKey privKey = kf.generatePrivate(privKeySpec);
            Signature signatureEngine = RsaSha256Fulfillment.getSignEngine();
            signatureEngine.initSign(privKey /*, saltRandom */);
            signatureEngine.update(message);
            byte[] signature =  signatureEngine.sign();
            BigInteger modulus = privKeySpec.getModulus();
            FulfillmentPayload payload = RsaSha256Fulfillment.calculatePayload(modulus, signature);
    
            return new RsaSha256Fulfillment(type, payload, modulus, new SignaturePayload(signature));
        } catch (Exception e) {
            throw new RuntimeException(e.toString(), e);
        }
    }

    /*FIXME public due to FulfillmentInputStream requirements*/
    public RsaSha256Fulfillment(ConditionType type, FulfillmentPayload payload, BigInteger modulus, SignaturePayload signature) {
        super(type, payload);
        // TODO: CHECK toString(10) fails with test-data
        int modulus_length = modulus.toString(16).length()/2;
        if (modulus_length < MINIMUM_MODULUS_SIZE ) {
            throw new RuntimeException("Modulus must be more than "
                    + Integer.toString(MINIMUM_MODULUS_SIZE) + " bytes.");
        }

        if (modulus_length > MAXIMUM_MODULUS_SIZE ) {
            throw new RuntimeException("Modulus must be less than "
                    + Integer.toString(MAXIMUM_MODULUS_SIZE) + " bytes.");
        }
        if (modulus_length != signature.payload.length) {
            throw new RuntimeException("Modulus and signature must be the same size.");
        }

        if (modulus.compareTo(new BigInteger(signature.payload)) < 0) { // TODO: > or >=
            throw new RuntimeException("Modulus must be larger, numerically, than signature.");
        }

        
        this.modulus = modulus;
        this.signature = signature.payload.clone();
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
    protected Condition generateCondition() {
System.out.println("deleteme generateCondition");
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
            Signature signatureEngine = RsaSha256Fulfillment.getSignEngine();
            PublicKey pubKey = kf.generatePublic(this.getPublicKey());
            signatureEngine.initVerify(pubKey);
            signatureEngine.update(message.payload);
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

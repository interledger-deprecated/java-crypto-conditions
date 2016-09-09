package org.interledger.cryptoconditions;

import java.math.BigInteger;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.EnumSet;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPrivateKeySpec;
//import java.security.spec.RSAPublicKeySpec;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.KeyFactory;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;


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

    public static RsaSha256Fulfillment BuildFromSecrets(KeyPayload privateKey, byte[] message) {
        ConditionType type = ConditionType.RSA_SHA256;
        RSAPrivateKeySpec privKey;
        try {
            privKey = (RSAPrivateKeySpec)kf.generatePrivate(new PKCS8EncodedKeySpec(privateKey.payload));
            signatureEngine.initSign((PrivateKey) privKey, new SecureRandom());
            BigInteger modulus = privKey.getModulus();
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
        if (modulus.compareTo(BigInteger.valueOf(MINIMUM_MODULUS_SIZE)) == -1) {
            throw new RuntimeException("Modulus must be more than "
                    + Integer.toString(MINIMUM_MODULUS_SIZE) + " bytes.");
        }

        if (modulus.compareTo(BigInteger.valueOf(MAXIMUM_MODULUS_SIZE)) == +1 ) {
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
        return ConditionType.PREIMAGE_SHA256;
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


  public static void main(String[] args) throws Exception {
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

    RSAPrivateKeySpec privKey;
    PublicKey pubKey;

    if (Boolean.parseBoolean("false") /*generate private key */) {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(512, new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();
        privKey = (RSAPrivateKeySpec)keyPair.getPrivate();
        pubKey = keyPair.getPublic();
    } else if (true /* read private key from Byte Array */) {
        byte[] privateKeyBytes = "adfafljkhlk ".getBytes();
        privKey = (RSAPrivateKeySpec)kf.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
        
        byte[] publicKeyBytes  = "asdlfjahdflak".getBytes();
        pubKey = kf.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
    }

    signatureEngine.initSign((PrivateKey) privKey, new SecureRandom());

    byte[] message = "abc".getBytes();
    signatureEngine.update(message);

    byte[] sigBytes = signatureEngine.sign();
    
    
    signatureEngine.initVerify(pubKey);
    signatureEngine.update(message);
    System.out.println(signatureEngine.verify(sigBytes));
  }
}

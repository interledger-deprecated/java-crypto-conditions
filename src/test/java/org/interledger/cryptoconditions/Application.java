package org.interledger.cryptoconditions;

import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPublicKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.interledger.cryptoconditions.der.CryptoConditionReader;
import org.interledger.cryptoconditions.der.DerEncodingException;
import org.interledger.cryptoconditions.types.Ed25519Sha256Condition;
import org.interledger.cryptoconditions.types.Ed25519Sha256Fulfillment;
import org.interledger.cryptoconditions.types.PrefixSha256Condition;
import org.interledger.cryptoconditions.types.PrefixSha256Fulfillment;
import org.interledger.cryptoconditions.types.PreimageSha256Condition;
import org.interledger.cryptoconditions.types.PreimageSha256Fulfillment;
import org.interledger.cryptoconditions.types.RsaSha256Condition;
import org.interledger.cryptoconditions.types.RsaSha256Fulfillment;
import org.interledger.cryptoconditions.types.ThresholdSha256Condition;
import org.interledger.cryptoconditions.types.ThresholdSha256Fulfillment;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAKeyGenParameterSpec;


/**
 * Playground / test class. Will be removed at a future date.
 */
public class Application {

  public static void main(String[] args) throws NoSuchAlgorithmException,
      InvalidAlgorithmParameterException, IOException, InvalidKeyException, SignatureException, DerEncodingException {

    Provider bc = new BouncyCastleProvider();
    System.out.println(bc.getInfo());
    Security.addProvider(bc);

    byte[] preimage = "Hello World!".getBytes(Charset.defaultCharset());
    byte[] prefix = "Ying ".getBytes(Charset.defaultCharset());
    byte[] message = "Yang".getBytes(Charset.defaultCharset());
    byte[] prefixedMessage = "Ying Yang".getBytes(Charset.defaultCharset());

    MessageDigest sha256Digest = MessageDigest.getInstance("SHA-256");
    MessageDigest sha512Digest = MessageDigest.getInstance("SHA-512");

    byte[] fingerprint = sha256Digest.digest(preimage);

    KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA");
    rsaKpg.initialize(new RSAKeyGenParameterSpec(2048, new BigInteger("65537")));
    KeyPair rsaKeyPair = rsaKpg.generateKeyPair();
    Signature rsaSigner = Signature.getInstance("SHA256withRSA/PSS");
    rsaSigner.initSign(rsaKeyPair.getPrivate());
    rsaSigner.update(message);
    byte[] rsaSignature = rsaSigner.sign();

    net.i2p.crypto.eddsa.KeyPairGenerator edDsaKpg = new net.i2p.crypto.eddsa.KeyPairGenerator();
    KeyPair edDsaKeyPair = edDsaKpg.generateKeyPair();
    Signature edDsaSigner = new EdDSAEngine(sha512Digest);
    edDsaSigner.initSign(edDsaKeyPair.getPrivate());
    edDsaSigner.update(prefix);
    edDsaSigner.update(message);
    byte[] edDsaSignature = edDsaSigner.sign();

    PreimageSha256Condition preimageCondition = new PreimageSha256Condition(preimage);
    RsaSha256Condition rsaCondition = new RsaSha256Condition((RSAPublicKey) rsaKeyPair.getPublic());
    Ed25519Sha256Condition ed25519Condition =
        new Ed25519Sha256Condition((EdDSAPublicKey) edDsaKeyPair.getPublic());
    PrefixSha256Condition prefixConditionOnEd25519Condition =
        new PrefixSha256Condition(prefix, 1000, ed25519Condition);
    ThresholdSha256Condition thresholdCondition = new ThresholdSha256Condition(2,
        new Condition[] {preimageCondition, rsaCondition, prefixConditionOnEd25519Condition});

    PreimageSha256Fulfillment preimageFulfillment = new PreimageSha256Fulfillment(preimage);
    RsaSha256Fulfillment rsaFulfillment =
        new RsaSha256Fulfillment((RSAPublicKey) rsaKeyPair.getPublic(), rsaSignature);
    Ed25519Sha256Fulfillment ed25519Fulfillment =
        new Ed25519Sha256Fulfillment((EdDSAPublicKey) edDsaKeyPair.getPublic(), edDsaSignature);
    PrefixSha256Fulfillment prefixFulfillmentOnEd25519Fulfillment =
        new PrefixSha256Fulfillment(prefix, 1000, ed25519Fulfillment);
    ThresholdSha256Fulfillment thresholdFulfillment =
        new ThresholdSha256Fulfillment(new Condition[] {rsaCondition},
            new Fulfillment[] {preimageFulfillment, prefixFulfillmentOnEd25519Fulfillment});

    hexDump("preimage", preimage);
    hexDump("prefix", prefix);
    hexDump("message", message);
    hexDump("fingerprint", fingerprint);
    hexDump("rsa_privatekey", rsaKeyPair.getPrivate().getEncoded());
    hexDump("rsa_publickey", rsaKeyPair.getPublic().getEncoded());
    hexDump("rsa_sig", rsaSignature);
    hexDump("eddsa_privatekey", edDsaKeyPair.getPrivate().getEncoded());
    hexDump("eddsa_publickey", edDsaKeyPair.getPublic().getEncoded());
    hexDump("eddsa_sig", edDsaSignature);

    hexDump("preimage_condition", preimageCondition.getEncoded());
    System.out.println("preimage_condition: " + preimageCondition.toString());
    hexDump("ed25519_condition", ed25519Condition.getEncoded());
    System.out.println("ed25519_condition: " + ed25519Condition.toString());
    hexDump("rsa_condition", rsaCondition.getEncoded());
    System.out.println("rsa_condition: " + rsaCondition.toString());
    hexDump("prefix_condition", prefixConditionOnEd25519Condition.getEncoded());
    System.out.println("prefix_condition: " + prefixConditionOnEd25519Condition.toString());
    hexDump("threshold_condition", thresholdCondition.getEncoded());
    System.out.println("threshold_condition: " + thresholdCondition.toString());

    byte[] encodedPreimageFulfillment = preimageFulfillment.getEncoded();
    byte[] encodedEd25519Fulfillment = ed25519Fulfillment.getEncoded();
    byte[] encodedRsaFulfillment = rsaFulfillment.getEncoded();
    byte[] encodedPrefixFulfillmentOnEd25519Fulfillment = prefixFulfillmentOnEd25519Fulfillment.getEncoded();
    byte[] encodedThresholdFulfillment = thresholdFulfillment.getEncoded();
    
    hexDump("preimage_fulfillment", encodedPreimageFulfillment);
    hexDump("ed25519_fulfillment", encodedEd25519Fulfillment);
    hexDump("rsa_fulfillment", encodedRsaFulfillment);
    hexDump("prefix_fulfillment", encodedPrefixFulfillmentOnEd25519Fulfillment);
    hexDump("threshold_fulfillment", encodedThresholdFulfillment);

    System.out.println("preimage : "
        + (preimageFulfillment.verify(preimageCondition, message) ? "VERIFIED" : "FAILED"));
    System.out
        .println("rsa : " + (rsaFulfillment.verify(rsaCondition, message) ? "VERIFIED" : "FAILED"));
    System.out.println("ed25519 : "
        + (ed25519Fulfillment.verify(ed25519Condition, prefixedMessage) ? "VERIFIED" : "FAILED"));
    System.out.println("prefix on ed25519 : "
        + (prefixFulfillmentOnEd25519Fulfillment.verify(prefixConditionOnEd25519Condition, message)
            ? "VERIFIED" : "FAILED"));
    System.out.println("threshold : "
        + (thresholdFulfillment.verify(thresholdCondition, message) ? "VERIFIED" : "FAILED"));

    PreimageSha256Fulfillment preimageFulfillment2 = (PreimageSha256Fulfillment) CryptoConditionReader.readFulfillment(encodedPreimageFulfillment);    
    PrefixSha256Fulfillment prefixFulfillment2 = (PrefixSha256Fulfillment) CryptoConditionReader.readFulfillment(encodedPrefixFulfillmentOnEd25519Fulfillment);    
    ThresholdSha256Fulfillment thresholdFulfillment2 = (ThresholdSha256Fulfillment) CryptoConditionReader.readFulfillment(encodedThresholdFulfillment);    
    RsaSha256Fulfillment rsaFulfillment2 = (RsaSha256Fulfillment) CryptoConditionReader.readFulfillment(encodedRsaFulfillment);    
    Ed25519Sha256Fulfillment ed25519Fulfillment2 = (Ed25519Sha256Fulfillment) CryptoConditionReader.readFulfillment(encodedEd25519Fulfillment);    
    
    System.out.println("decoded preimage: " + preimageFulfillment2.toString());
    System.out.println("decoded prefix: " + prefixFulfillment2.toString());
    System.out.println("decoded threshold: " + thresholdFulfillment2.toString());
    System.out.println("decoded rsa: " + rsaFulfillment2.toString());
    System.out.println("decoded ed25519: " + ed25519Fulfillment2.toString());

  }

  private static void hexDump(String label, byte[] bytes) {
    System.out.print("<" + label + ">");
    System.out.println(HexDump.dumpHexString(bytes));
    System.out.println("</" + label + ">");
  }

}

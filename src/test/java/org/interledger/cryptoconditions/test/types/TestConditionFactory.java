package org.interledger.cryptoconditions.test.types;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import org.interledger.cryptoconditions.Condition;
import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.UnsignedBigInteger;
import org.interledger.cryptoconditions.test.TestCondition;
import org.interledger.cryptoconditions.test.TestVectorJson;

import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

public class TestConditionFactory {

  public static TestCondition getTestConditionFromTestVectorJson(TestVectorJson condition) {
    
    ConditionType type = ConditionType.fromString(condition.getType());
    
    switch(type) {
      
      case PREIMAGE_SHA256:
        return new TestPreimageSha256Condition(
            Base64.getUrlDecoder().decode(condition.getPreimage()));
      
      case PREFIX_SHA256:
        return new TestPrefixSha256Condition(
            Base64.getUrlDecoder().decode(condition.getPrefix()),
            condition.getMaxMessageLength(),
            getTestConditionFromTestVectorJson(condition.getSubfulfillment()));
      
      case THRESHOLD_SHA256:
        List<Condition> subconditions = new ArrayList<>();
        for (TestVectorJson vector : condition.getSubfulfillments()) {
          subconditions.add(getTestConditionFromTestVectorJson(vector));
        }
        return new TestThresholdSha256Condition(
            condition.getThreshold(),
            subconditions.toArray(new Condition[subconditions.size()]));
        
      case RSA_SHA256:
        
        byte[] modulusBytes = Base64.getUrlDecoder().decode(condition.getModulus());
        BigInteger modulus = UnsignedBigInteger.fromUnsignedByteArray(modulusBytes);
        BigInteger exponent = BigInteger.valueOf(65537);
        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
        try {
          KeyFactory keyFactory = KeyFactory.getInstance("RSA");
          RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(spec);
          return new TestRsaSha256Condition(publicKey);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
          throw new RuntimeException("Error creating RSA key.", e);
        }
        
      case ED25519_SHA256:
        
        byte[] publicKeyBytes = Base64.getUrlDecoder().decode(condition.getPublicKey());
        
        EdDSAPublicKeySpec publicKeyspec = new EdDSAPublicKeySpec(
            publicKeyBytes, 
            EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.CURVE_ED25519_SHA512));
        EdDSAPublicKey publicKey = new EdDSAPublicKey(publicKeyspec);
        return new TestEd25519Sha256Condition(publicKey);
        
      default:
        throw new RuntimeException("Unknown type."); 
    }
        
  }
}

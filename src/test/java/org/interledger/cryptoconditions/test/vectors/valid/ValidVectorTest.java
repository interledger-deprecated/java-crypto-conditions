package org.interledger.cryptoconditions.test.vectors.valid;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.interledger.cryptoconditions.Condition;
import org.interledger.cryptoconditions.Fulfillment;
import org.interledger.cryptoconditions.HexDump;
import org.interledger.cryptoconditions.UnsignedBigInteger;
import org.interledger.cryptoconditions.der.CryptoConditionReader;
import org.interledger.cryptoconditions.der.DerEncodingException;
import org.interledger.cryptoconditions.test.CryptoConditionAssert;
import org.interledger.cryptoconditions.test.TestVector;
import org.interledger.cryptoconditions.test.types.TestConditionFactory;
import org.interledger.cryptoconditions.types.Ed25519Sha256Fulfillment;
import org.interledger.cryptoconditions.types.PrefixSha256Fulfillment;
import org.interledger.cryptoconditions.types.PreimageSha256Fulfillment;
import org.interledger.cryptoconditions.types.RsaSha256Fulfillment;
import org.interledger.cryptoconditions.types.ThresholdSha256Fulfillment;
import org.interledger.cryptoconditions.uri.CryptoConditionUri;
import org.interledger.cryptoconditions.uri.UriEncodingException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import java.io.File;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URL;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;

/**
 * Test the implementation of crypto-conditions based on a set of pre-computed and validated test
 * vectors.
 */
@RunWith(Parameterized.class)
public class ValidVectorTest {

  private TestVector testVector;
  
  public ValidVectorTest(TestVector testVector) throws Exception {
    this.testVector = testVector;
  }

  /**
   * Loads a list of tests based on the json-encoded test vector files.
   */
  @Parameters(name = "Test Vector {index}: {0}")
  public static Collection<TestVector> testVectors() throws Exception {

    URL classUri =
        ValidVectorTest.class.getResource(ValidVectorTest.class.getSimpleName() + ".class");
    File dir = new File(classUri.toURI()).getParentFile();

    List<TestVector> vectors = new ArrayList<>();
    ObjectMapper mapper = new ObjectMapper();

    for (File file : dir.listFiles()) {
      if (file.getName().endsWith(".json")) {
        TestVector vector = mapper.readValue(file, TestVector.class);
        vector.setName(file.getName().substring(0, file.getName().length() - 5));
        vectors.add(vector);
      }
    }
    
    return vectors;
  }



  // according to the source of the test 'vectors' (https://github.com/rfcs/crypto-conditions),
  // we should test by
  // - parse the conditionBinary content, serializing as a uri and comparing to conditionUri
  // - parse conditionUri, serialize to binary, and compare to conditionBinary
  // TODO:
  // - Parse fulfillment, serialize fulfillment, should match fulfillment.
  // - Parse fulfillment and validate, should return true.
  // - Parse fulfillment and generate the fingerprint contents
  // - Parse fulfillment, generate the condition, serialize the condition as a URI, should match
  // conditionUri.
  // - Create fulfillment from json, serialize fulfillment, should match fulfillment.

  @Test
  public void testCost() throws UriEncodingException, DerEncodingException {

    long testCost = testVector.getCost();
    long calculatedCost =
        TestConditionFactory.getTestConditionFromTestVectorJson(testVector.getJson()).getCost();
    assertEquals(testVector.getName() + " [compare cost and calculated cost]", testCost,
        calculatedCost);
  }

  @Test
  public void testFingerPrintContent() throws DerEncodingException {

    byte[] testFingerprintContents =
        HexDump.hexStringToByteArray(testVector.getFingerprintContents());
    byte[] encodedFingerprintContents = TestConditionFactory
        .getTestConditionFromTestVectorJson(testVector.getJson()).getUnhashedFingerprint();
    assertArrayEquals(
        testVector.getName() + " [compare fingerprint contents and encoded fingerprint contents]",
        testFingerprintContents, encodedFingerprintContents);
  }

  @Test
  public void testParseCondition() throws UriEncodingException, DerEncodingException {

    Condition binaryCondition = CryptoConditionReader
        .readCondition(HexDump.hexStringToByteArray(testVector.getConditionBinary()));
    Condition testCondition =
        TestConditionFactory.getTestConditionFromTestVectorJson(testVector.getJson());

    assertEquals(testVector.getName() + " [compare binary condition and test condition]",
        testCondition, binaryCondition);

  }

  @Test
  public void testParseConditionAndGenerateUri()
      throws UriEncodingException, DerEncodingException, UnsupportedEncodingException {

    Condition binaryCondition = CryptoConditionReader
        .readCondition(HexDump.hexStringToByteArray(testVector.getConditionBinary()));

    CryptoConditionAssert.assertUriEqual(testVector.getName() + " [binary condition => uri]",
        URI.create(testVector.getConditionUri()), binaryCondition.getUri());
  }

  @Test
  public void testParseConditionUriAndGenerateBinary() throws UriEncodingException {

    Condition uriCondition = CryptoConditionUri.parse(URI.create(testVector.getConditionUri()));
    assertEquals(testVector.getName() + " [condition uri => binary]",
        testVector.getConditionBinary(), HexDump.toHexString(uriCondition.getEncoded()));

  }

  @Test
  public void testParseFulfillmentAndCheckProperties() throws Exception {
    byte[] fulfillmentBytes = HexDump.hexStringToByteArray(testVector.getFulfillment());
    Fulfillment fulfillment = CryptoConditionReader.readFulfillment(fulfillmentBytes);

    switch (fulfillment.getType()) {
      case PREIMAGE_SHA256:
        PreimageSha256Fulfillment preimageFulfillment = (PreimageSha256Fulfillment) fulfillment;
        assertArrayEquals(testVector.getName() + " [compare preimage]",
            Base64.getUrlDecoder().decode(testVector.getJson().getPreimage()),
            preimageFulfillment.getPreimage());
        break;

      case PREFIX_SHA256:
        PrefixSha256Fulfillment prefixFulfillment = (PrefixSha256Fulfillment) fulfillment;
        assertArrayEquals(testVector.getName() + " [compare prefix]",
            Base64.getUrlDecoder().decode(testVector.getJson().getPrefix()),
            prefixFulfillment.getPrefix());
        assertEquals(testVector.getName() + " [compare max message length]",
            testVector.getJson().getMaxMessageLength(), prefixFulfillment.getMaxMessageLength());
        CryptoConditionAssert.assertSetOfTypesIsEqual(testVector.getName() + " [compare subtypes]",
            testVector.getSubtypes(), prefixFulfillment.getCondition().getSubtypes());

        // TODO Should we test for equality of subfulfillments?
        break;

      case THRESHOLD_SHA256:
        ThresholdSha256Fulfillment thresholdFulfillment = (ThresholdSha256Fulfillment) fulfillment;
        assertEquals(testVector.getName() + " [compare threshold]",
            testVector.getJson().getThreshold(), thresholdFulfillment.getThreshold());
        CryptoConditionAssert.assertSetOfTypesIsEqual(testVector.getName() + " [compare subtypes]",
            testVector.getSubtypes(), thresholdFulfillment.getCondition().getSubtypes());
        // TODO Should we test for equality of subfulfillments and subconditions?
        break;

      case RSA_SHA256:
        RsaSha256Fulfillment rsaFulfillment = (RsaSha256Fulfillment) fulfillment;
        assertArrayEquals(testVector.getName() + " [compare rsa key modulus]",
            Base64.getUrlDecoder().decode(testVector.getJson().getModulus()),
            UnsignedBigInteger.toUnsignedByteArray(rsaFulfillment.getPublicKey().getModulus()));
        assertArrayEquals(testVector.getName() + " [compare rsa signature]",
            Base64.getUrlDecoder().decode(testVector.getJson().getSignature()),
            rsaFulfillment.getSignature());
        break;

      case ED25519_SHA256:
        Ed25519Sha256Fulfillment ed25519Fulfillment = (Ed25519Sha256Fulfillment) fulfillment;
        assertArrayEquals(testVector.getName() + " [compare ed25519 key]",
            Base64.getUrlDecoder().decode(testVector.getJson().getPublicKey()),
            ed25519Fulfillment.getPublicKey().getAbyte());
        assertArrayEquals(testVector.getName() + " [compare signature]",
            Base64.getUrlDecoder().decode(testVector.getJson().getSignature()),
            ed25519Fulfillment.getSignature());
        break;

      default:
        throw new Exception("Unknown fulfillment type: " + fulfillment.getType());
    }
  }

  @Test
  public void testParseFulfillmentAndReserialize()
      throws UriEncodingException, DerEncodingException {
    byte[] fulfillmentBytes = HexDump.hexStringToByteArray(testVector.getFulfillment());
    Fulfillment binaryFulfillment = CryptoConditionReader.readFulfillment(fulfillmentBytes);
    assertArrayEquals(testVector.getName() + " [fulfillment deserialize/reserialize]",
        fulfillmentBytes, binaryFulfillment.getEncoded());
  }

  @Test
  public void testParseFulfillmentAndGenerateCondtion()
      throws UriEncodingException, DerEncodingException {
    byte[] fulfillmentBytes = HexDump.hexStringToByteArray(testVector.getFulfillment());
    Fulfillment fulfillment = CryptoConditionReader.readFulfillment(fulfillmentBytes);
    Condition derivedCondition = fulfillment.getCondition();
    Condition condition = CryptoConditionUri.parse(URI.create(testVector.getConditionUri()));

    assertEquals(testVector.getName() + " [fulfillment derive condition]", condition,
        derivedCondition);
  }

  @Test
  public void testParseFulfillmentAndValidate() throws UriEncodingException, DerEncodingException {
    byte[] fulfillmentBytes = HexDump.hexStringToByteArray(testVector.getFulfillment());
    byte[] message = (testVector.getMessage() != null)
        ? HexDump.hexStringToByteArray(testVector.getMessage()) : new byte[] {};

    Fulfillment fulfillment = CryptoConditionReader.readFulfillment(fulfillmentBytes);
    Condition condition = CryptoConditionUri.parse(URI.create(testVector.getConditionUri()));

    assertTrue(testVector.getName() + " [fulfillment validate]",
        fulfillment.verify(condition, message));
  }

  static {
    // Need to add BouncyCastle so we have a provider that supports SHA256withRSA/PSS signatures
    Provider bc = new BouncyCastleProvider();
    Security.addProvider(bc);
  }

}


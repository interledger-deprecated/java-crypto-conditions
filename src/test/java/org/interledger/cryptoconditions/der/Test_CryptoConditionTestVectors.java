package org.interledger.cryptoconditions.der;

import static org.junit.Assert.*;

import java.io.InputStream;
import java.net.URI;
import java.util.Arrays;
import java.util.Collection;

import org.interledger.cryptoconditions.Condition;
import org.interledger.cryptoconditions.Fulfillment;
import org.interledger.cryptoconditions.HexDump;
import org.interledger.cryptoconditions.test.TestVector;
import org.interledger.cryptoconditions.uri.CryptoConditionUri;
import org.interledger.cryptoconditions.uri.URIEncodingException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Test the implementation of crypto-condition parsing from/to uri's and binary
 */
@RunWith(Parameterized.class)
public class Test_CryptoConditionTestVectors {

  @Parameters
  public static Collection<String> testVectors() {
    return Arrays.asList(new String[] {
        "0000_test-minimal-preimage.json",
        "0001_test-minimal-prefix.json",
        "0002_test-minimal-threshold.json",
        "0003_test-minimal-rsa.json",
        "0004_test-minimal-ed25519.json",
        "0005_test-basic-preimage.json",
        "0006_test-basic-prefix.json",
        "0007_test-basic-prefix-two-levels-deep.json",
        "0008_test-basic-threshold.json",
        "0009_test-basic-threshold-same-condition-twice.json",
        "0010_test-basic-threshold-same-fulfillment-twice.json",
        "0011_test-basic-threshold-two-levels-deep.json",
        "0012_test-basic-threshold-schroedinger.json",
        "0013_test-basic-rsa.json",
        "0014_test-basic-rsa4096.json",
        "0015_test-basic-ed25519.json",
        "0016_test-advanced-notarized-receipt.json",
        "0017_test-advanced-notarized-receipt-multiple-notaries.json"});
  }
  
  private TestVector testVector;
  private String vectorName;
  
  public Test_CryptoConditionTestVectors(String vectorName) throws Exception {
    this.vectorName = vectorName;
    
    ObjectMapper m = new ObjectMapper();
    try(InputStream is = getClass().getClassLoader().getResourceAsStream(vectorName)) {
        testVector = m.readValue(is, TestVector.class);
    }
  }
  
  // according to the source of the test 'vectors' (https://github.com/rfcs/crypto-conditions),
  // we should test by
  // - parse the conditionBinary content, serializing as a uri and comparing to conditionUri
  // - parse conditionUri, serialize to binary, and compare to conditionBinary
  // TODO:
  // - Parse fulfillment, serialize fulfillment, should match fulfillment.
  // - Parse fulfillment and validate, should return true.
  // - Parse fulfillment and generate the fingerprint contents
  // - Parse fulfillment, generate the condition, serialize the condition as a URI, should match conditionUri.
  // - Create fulfillment from json, serialize fulfillment, should match fulfillment.
  
  @Test
  public void testParseConditionAndGenerateUri() throws URIEncodingException, DEREncodingException {
    
    Condition binaryCondition = CryptoConditionReader.readCondition(HexDump.hexStringToByteArray(testVector.getConditionBinary()));
    assertEquals(vectorName + " [binary condition => uri]", testVector.getConditionUri(), binaryCondition.getUri().toString());
    
  }
  
  @Test
  public void testParseConditionUriAndGenerateBinary() throws URIEncodingException {
    
    Condition uriCondition = CryptoConditionUri.parse(URI.create(testVector.getConditionUri()));
    assertEquals(vectorName + " [condition uri => binary]", testVector.getConditionBinary(), HexDump.toHexString(uriCondition.getEncoded()));
    
  }
  
  @Test
  public void testParseFulfillmentAndReserialize() throws URIEncodingException, DEREncodingException {
    byte[] fulfillmentBytes = HexDump.hexStringToByteArray(testVector.getFulfillment());
    Fulfillment binaryFulfillment = CryptoConditionReader.readFulfillment(fulfillmentBytes);
    assertArrayEquals(vectorName + " [fulfillment deserialize/reserialize]", fulfillmentBytes, binaryFulfillment.getEncoded());    
  }
  
  @Test
  public void testParseFulfillmentAndValidate() throws URIEncodingException, DEREncodingException {
    byte[] fulfillmentBytes = HexDump.hexStringToByteArray(testVector.getFulfillment());
    byte[] message = (testVector.getMessage() != null) ? HexDump.hexStringToByteArray(testVector.getMessage()) : new byte[]{};
    
    Fulfillment fulfillment = CryptoConditionReader.readFulfillment(fulfillmentBytes);
    Condition condition = CryptoConditionUri.parse(URI.create(testVector.getConditionUri()));

    assertTrue(vectorName + " [fulfillment validate]", fulfillment.verify(condition, message));    
  }
  
  
  
  
}


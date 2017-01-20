package org.interledger.cryptoconditions.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.EnumSet;

import org.interledger.cryptoconditions.ConditionType;
import org.junit.Test;

public class Test_ConditionType {

  @Test
  public void test_fromString_case_insensitive() {
    assertEquals(ConditionType.PREFIX_SHA256, ConditionType.fromString("PREFIX-SHA-256"));
    assertEquals(ConditionType.PREFIX_SHA256, ConditionType.fromString("prefix-SHA-256"));
    assertEquals(ConditionType.PREFIX_SHA256, ConditionType.fromString("prefix-sha-256"));
    assertEquals(ConditionType.ED25519_SHA256, ConditionType.fromString("ED25519-SHA-256"));
    assertEquals(ConditionType.ED25519_SHA256, ConditionType.fromString("ed25519-sha-256"));
    assertEquals(ConditionType.ED25519_SHA256, ConditionType.fromString("ED25519-sha-256"));
  }
  
  @Test
  public void test_getEnumOfTypesAsBitString_None() {
    EnumSet<ConditionType> set = EnumSet.noneOf(ConditionType.class);
    
    byte[] bitSet = ConditionType.getEnumOfTypesAsBitString(set);
    
    assertNotNull(bitSet);
    assertEquals(1, bitSet.length);
    assertEquals(0, bitSet[0]);
  }
  
  @Test
  public void test_getEnumOfTypesAsBitString_All() {
    EnumSet<ConditionType> set = EnumSet.allOf(ConditionType.class);
    
    byte[] bitSet = ConditionType.getEnumOfTypesAsBitString(set);
    
    assertNotNull(bitSet);
    assertEquals(2, bitSet.length);
    //the bit string should be '11111', right padded to 8 bits. the first byte is the pad length
    assertEquals(3, bitSet[0]);
    assertEquals(0xF8, Byte.toUnsignedInt(bitSet[1])); 
  }

  @Test
  public void test_getEnumOfTypesAsBitString_LSB() {
    EnumSet<ConditionType> set = EnumSet.of(ConditionType.PREIMAGE_SHA256);
    
    byte[] bitSet = ConditionType.getEnumOfTypesAsBitString(set);
    
    assertNotNull(bitSet);
    assertEquals(2, bitSet.length);
    //the bit string should be '1', right padded to 8 bits. the first byte is the pad length
    assertEquals(7, bitSet[0]);
    assertEquals(0x80, Byte.toUnsignedInt(bitSet[1])); 
  }
  
  @Test
  public void test_getEnumOfTypesAsBitString_MSB() {
    EnumSet<ConditionType> set = EnumSet.of(ConditionType.ED25519_SHA256);
    
    byte[] bitSet = ConditionType.getEnumOfTypesAsBitString(set);
    
    assertNotNull(bitSet);
    assertEquals(2, bitSet.length);
    //the bit string should be '00001', right padded to 8 bits. the first byte is the pad length
    assertEquals(3, bitSet[0]);
    assertEquals(0x08, Byte.toUnsignedInt(bitSet[1])); 
  }
  
  @Test
  public void test_getEnumOfTypesFromBitString_All() {
    EnumSet<ConditionType> set = ConditionType.getEnumOfTypesFromBitString(new byte[] {0x03, (byte) 0xF8});
    
    assertNotNull(set);
    assertEquals(EnumSet.allOf(ConditionType.class), set);
  }

  @Test
  public void test_getEnumOfTypesFromBitString_MSB() {
    EnumSet<ConditionType> set = ConditionType.getEnumOfTypesFromBitString(new byte[] {0x03, (byte) 0x08});
    
    assertNotNull(set);
    assertEquals(1, set.size());
    assertTrue(set.contains(ConditionType.ED25519_SHA256));
  }

  @Test
  public void test_getEnumOfTypesFromBitString_LSB() {
    EnumSet<ConditionType> set = ConditionType.getEnumOfTypesFromBitString(new byte[] {0x07, (byte) 0x80});
    
    assertNotNull(set);
    assertEquals(1, set.size());
    assertTrue(set.contains(ConditionType.PREIMAGE_SHA256));
  }
  
  @Test
  public void test_getEnumOfTypesAsString_None() {
    EnumSet<ConditionType> set = EnumSet.noneOf(ConditionType.class);
    String s = ConditionType.getEnumOfTypesAsString(set);
    
    assertNotNull(s);
    assertEquals("", s);
  }
  
  @Test
  public void test_getEnumOfTypesAsString_All() {
    EnumSet<ConditionType> set = EnumSet.allOf(ConditionType.class);
    String s = ConditionType.getEnumOfTypesAsString(set);
    
    assertNotNull(s);
    assertEquals("preimage-sha-256,prefix-sha-256,threshold-sha-256,rsa-sha-256,ed25519-sha-256", s);
  }
  
  @Test
  public void test_getEnumOfTypesFromString_None() {
    EnumSet<ConditionType> set = ConditionType.getEnumOfTypesFromString("");

    assertNotNull(set);
    assertTrue(set.isEmpty());
  }
  
  @Test
  public void test_getEnumOfTypesFromString_All() {
    String list = "preimage-sha-256,prefix-sha-256,threshold-sha-256,rsa-sha-256,ed25519-sha-256";
    EnumSet<ConditionType> set = ConditionType.getEnumOfTypesFromString(list);

    assertNotNull(set);
    assertEquals(EnumSet.allOf(ConditionType.class), set);
  }
  
}


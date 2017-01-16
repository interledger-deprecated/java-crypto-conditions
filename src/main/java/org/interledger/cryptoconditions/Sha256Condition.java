package org.interledger.cryptoconditions;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Abstract base class for the *-SHA-256 condition types.
 * 
 * Provides concrete implementation of generation of 
 * SHA256 fingerprint via a shared static digest.
 *  
 * @author adrianhopebailie
 *
 */
public abstract class Sha256Condition extends ConditionBase {

  private byte[] fingerprint;

  protected Sha256Condition(long cost) {
    super(cost);
  }

  protected Sha256Condition(byte[] fingerprint, long cost) {
    super(cost);
    this.fingerprint = fingerprint;
    
    if(fingerprint.length != 32) {
      throw new IllegalArgumentException("Fingerprint must be 32 bytes.");
    }
  }

  /**
   * Super-classes must provide the un-hashed fingerprint content
   * for this condition as defined in the specification.
   * 
   * @return
   */
  protected abstract byte[] getFingerprintContents();

  /**
   * Generates and caches the fingerprint on first call.
   * 
   * Returns a copy of the internally cached fingerprint.
   */
  @Override
  public byte[] getFingerprint() {
    if (fingerprint == null) {
      fingerprint = getDigest(getFingerprintContents());
    }
    
    byte[] returnVal = new byte[fingerprint.length];
    System.arraycopy(fingerprint, 0, returnVal, 0, fingerprint.length);
    
    return returnVal;
  }

  private static MessageDigest _DIGEST;

  private static byte[] getDigest(byte[] input) {
    if (_DIGEST == null) {
      try {
        _DIGEST = MessageDigest.getInstance("SHA-256");
      } catch (NoSuchAlgorithmException e) {
        throw new RuntimeException(e);
      }
    }

    return _DIGEST.digest(input);
  }

}

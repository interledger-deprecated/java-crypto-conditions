package org.interledger.cryptoconditions;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Abstract base class for the *-SHA-256 condition types.
 * 
 * <p>Provides a concrete implementation for the generation of a SHA256 fingerprint via a shared 
 * static digest.
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

    if (fingerprint.length != 32) {
      throw new IllegalArgumentException("Fingerprint must be 32 bytes.");
    }
  }

  /**
   * Returns the un-hashed fingerprint content for this condition as defined in the specification.
   */
  protected abstract byte[] getFingerprintContents();

  /**
   * Returns a copy of the (internally generated and cached) fingerprint on first call.
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

  //TODO: we should consider making this public and non-static, so that other classes could simply 
  //override this method to implement other digests (e.g. SHA512 etc)?
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

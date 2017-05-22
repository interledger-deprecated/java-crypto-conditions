package org.interledger.cryptoconditions;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Abstract base class for the *-SHA-256 condition types. Provides concrete implementation of
 * generation of SHA256 fingerprint via a shared static digest.
 */
public abstract class Sha256Condition extends ConditionBase {

  // This is not static because all of the instances returned from MessageDigest.getInstance() are
  // distinct in order to maintain separate digests.  Additionally, MessageDigest isn't
  // particularly expensive to construct (see MessageDigest source).
  private final MessageDigest messageDigest;

  private byte[] fingerprint;

  protected Sha256Condition(long cost) {
    super(cost);
    try {
      this.messageDigest = MessageDigest.getInstance("SHA-256");
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  protected Sha256Condition(byte[] fingerprint, long cost) {
    super(cost);
    this.fingerprint = fingerprint;

    if (fingerprint.length != 32) {
      throw new IllegalArgumentException("Fingerprint must be 32 bytes.");
    }

    try {
      this.messageDigest = MessageDigest.getInstance("SHA-256");
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * This method allows sub-classes to provide the fingerprint contents (un-hashed) so
   * that {@link #getFingerprint()} can be lazily computed.
   */
  protected abstract byte[] getFingerprintContents();

  /**
   * Generates and caches the fingerprint on first call. Returns a copy of the internally cached
   * fingerprint once constructed.  This is lazily computed because some
   * implementation's fingerprints involve a full ASN.1 DER serialization, which might be
   * expensive if the fingerprint is not needed.
   */
  @Override
  public byte[] getFingerprint() {
    if (fingerprint == null) {
      fingerprint = getDigest(getFingerprintContents());
    }

    return Arrays.copyOf(fingerprint, fingerprint.length);
  }

  private byte[] getDigest(byte[] input) {
    return messageDigest.digest(input);
  }

}

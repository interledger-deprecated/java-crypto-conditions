package org.interledger.cryptoconditions.types;

import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPublicKey;

import org.interledger.cryptoconditions.Condition;
import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.Fulfillment;
import org.interledger.cryptoconditions.der.DerOutputStream;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;


/**
 * Implements a fulfullment using the ED-25519 and SHA-256 functions.
 */
public class Ed25519Sha256Fulfillment implements Fulfillment {

  private Ed25519Sha256Condition condition;
  private EdDSAPublicKey publicKey;
  private byte[] signature;

  /**
   * Constructs an instance of the fulfillment.
   * 
   * @param publicKey   The public key associated with the condition and fulfillment.
   * @param signature   The signature associated with the fulfillment.
   */
  public Ed25519Sha256Fulfillment(EdDSAPublicKey publicKey, byte[] signature) {
    this.signature = new byte[signature.length];
    System.arraycopy(signature, 0, this.signature, 0, signature.length);
    this.publicKey = publicKey;
  }

  @Override
  public ConditionType getType() {
    return ConditionType.ED25519_SHA256;
  }

  /**
   * Returns the public key used.
   */
  public EdDSAPublicKey getPublicKey() {
    return publicKey;
  }

  /**
   * Returns a copy of the signature linked to this fulfillment.
   */
  public byte[] getSignature() {
    byte[] signature = new byte[this.signature.length];
    System.arraycopy(this.signature, 0, signature, 0, this.signature.length);
    return signature;
  }

  @Override
  public byte[] getEncoded() {
    try {
      // Build preimage sequence
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      DerOutputStream out = new DerOutputStream(baos);
      out.writeTaggedObject(0, publicKey.getA().toByteArray());
      out.writeTaggedObject(1, signature);
      out.close();
      byte[] buffer = baos.toByteArray();

      // Wrap CHOICE
      baos = new ByteArrayOutputStream();
      out = new DerOutputStream(baos);
      out.writeTaggedConstructedObject(getType().getTypeCode(), buffer);
      out.close();

      return baos.toByteArray();

    } catch (IOException e) {
      throw new UncheckedIOException("DER Encoding Error", e);
    }
  }

  @Override
  public Ed25519Sha256Condition getCondition() {
    if (condition == null) {
      condition = new Ed25519Sha256Condition(publicKey);
    }
    return condition;
  }

  @Override
  public boolean verify(Condition condition, byte[] message) {

    if (condition == null) {
      throw new IllegalArgumentException(
          "Can't verify a Ed25519Sha256Fulfillment against an null condition.");
    }

    if (!(condition instanceof Ed25519Sha256Condition)) {
      throw new IllegalArgumentException(
          "Must verify a Ed25519Sha256Fulfillment against Ed25519Sha256Condition.");
    }

    if (!getCondition().equals(condition)) {
      return false;
    }

    try {
      Signature edDsaSigner = new EdDSAEngine(getSha512Digest());
      edDsaSigner.initVerify(publicKey);
      edDsaSigner.update(message);
      return edDsaSigner.verify(signature);
    } catch (InvalidKeyException | SignatureException e) {
      // TODO Log error or throw?
      e.printStackTrace();
      return false;
    }

  }

  private static MessageDigest _DIGEST;

  private static MessageDigest getSha512Digest() {
    if (_DIGEST == null) {
      try {
        // TODO: i havent read up on fulfillments, but this seems counter-intuitive - why is this
        // class called ...Sha256, but we use a 512 digest? If this is right, we should definitely
        // include some comments here to explain.
        _DIGEST = MessageDigest.getInstance("SHA-512");
      } catch (NoSuchAlgorithmException e) {
        throw new RuntimeException(e);
      }
    }

    return _DIGEST;
  }
}

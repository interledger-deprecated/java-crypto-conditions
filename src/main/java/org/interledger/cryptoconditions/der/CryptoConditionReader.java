package org.interledger.cryptoconditions.der;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.interledger.cryptoconditions.Condition;
import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.Fulfillment;
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

import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

public class CryptoConditionReader {

  public static Condition readCondition(byte[] buffer) throws DEREncodingException {
    return readCondition(buffer, 0, buffer.length);
  }

  public static Condition readCondition(byte[] buffer, int offset, int length)
      throws DEREncodingException {

    ByteArrayInputStream bais = new ByteArrayInputStream(buffer, offset, length);
    DERInputStream in = new DERInputStream(bais);

    try {
      Condition c = readCondition(in);
      return c;
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    } finally {
      try {
        in.close();
      } catch (IOException e) {
        throw new UncheckedIOException(e);
      }
    }
  }

  public static Condition readCondition(DERInputStream in)
      throws DEREncodingException, IOException {
    return readCondition(in, new AtomicInteger());
  }

  public static Condition readCondition(DERInputStream in, AtomicInteger bytesRead)
      throws DEREncodingException, IOException {

    int tag = in.readTag(bytesRead, DERTags.CONSTRUCTED, DERTags.TAGGED);
    ConditionType type = ConditionType.valueOf(tag);
    int length = in.readLength(bytesRead);

    AtomicInteger innerBytesRead = new AtomicInteger();
    byte[] fingerprint = in.readTaggedObject(0, length - innerBytesRead.get(), innerBytesRead).getValue();
    long cost =
        new BigInteger(in.readTaggedObject(1, length - innerBytesRead.get(), innerBytesRead).getValue())
            .longValue();
    EnumSet<ConditionType> subtypes = null;
    if (type == ConditionType.PREFIX_SHA256 || type == ConditionType.THRESHOLD_SHA256) {
      subtypes = ConditionType.getEnumOfTypesFromBitString(
          in.readTaggedObject(2, length - innerBytesRead.get(), innerBytesRead).getValue());
    }
    bytesRead.addAndGet(innerBytesRead.get());

    switch (type) {
      case PREIMAGE_SHA256:
        return new PreimageSha256Condition(fingerprint, cost);
      case PREFIX_SHA256:
        return new PrefixSha256Condition(fingerprint, cost, subtypes);
      case THRESHOLD_SHA256:
        return new ThresholdSha256Condition(fingerprint, cost, subtypes);
      case RSA_SHA256:
        return new RsaSha256Condition(fingerprint, cost);
      case ED25519_SHA256:
        return new Ed25519Sha256Condition(fingerprint, cost);
    }

    throw new DEREncodingException("Unrecogized tag: " + tag);

  }
    
  public static Fulfillment readFulfillment(byte[] buffer) throws DEREncodingException {
    return readFulfillment(buffer, 0, buffer.length);
  }

  public static Fulfillment readFulfillment(byte[] buffer, int offset, int length)
      throws DEREncodingException {

    ByteArrayInputStream bais = new ByteArrayInputStream(buffer, offset, length);
    DERInputStream in = new DERInputStream(bais);

    try {
      return readFulfillment(in);
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    } finally {
      try {
        in.close();
      } catch (IOException e) {
        throw new UncheckedIOException(e);
      }
    }
  }

  public static Fulfillment readFulfillment(DERInputStream in)
      throws DEREncodingException, IOException {
    return readFulfillment(in, new AtomicInteger());
  }

  // TODO No length checks
  public static Fulfillment readFulfillment(DERInputStream in, AtomicInteger bytesRead)
      throws DEREncodingException, IOException {

    int tag = in.readTag(bytesRead, DERTags.CONSTRUCTED, DERTags.TAGGED);
    ConditionType type = ConditionType.valueOf(tag);
    int length = in.readLength(bytesRead);

    if(length == 0) {
      throw new DEREncodingException("Encountered an empty fulfillment.");      
    }

    AtomicInteger innerBytesRead = new AtomicInteger();
    switch (type) {
      case PREIMAGE_SHA256:

        byte[] preimage =
            in.readTaggedObject(0, length - innerBytesRead.get(), innerBytesRead).getValue();

        bytesRead.addAndGet(innerBytesRead.get());

        return new PreimageSha256Fulfillment(preimage);

      case PREFIX_SHA256:

        byte[] prefix = in.readTaggedObject(0, length - innerBytesRead.get(), innerBytesRead).getValue();
        long maxMessageLength = new BigInteger(
            in.readTaggedObject(1, length - innerBytesRead.get(), innerBytesRead).getValue()).longValue();

        tag = in.readTag(2, innerBytesRead, DERTags.CONSTRUCTED, DERTags.TAGGED);
        length = in.readLength(innerBytesRead);

        Fulfillment subfulfillment = readFulfillment(in, innerBytesRead);

        bytesRead.addAndGet(innerBytesRead.get());

        return new PrefixSha256Fulfillment(prefix, maxMessageLength, subfulfillment);

      case THRESHOLD_SHA256:

        List<Fulfillment> subfulfillments = new ArrayList<>();

        tag = in.readTag(innerBytesRead, DERTags.CONSTRUCTED, DERTags.TAGGED);
        length = in.readLength(innerBytesRead);

        // It is legal (per the encoding rules) for a THRESHOLD fulfillment to have only
        // sub-conditions even though it will never validate so we need to check if we've
        // skipped tag number 0
        if (tag == 0) {

          AtomicInteger subfulfillmentsBytesRead = new AtomicInteger();
          while (subfulfillmentsBytesRead.get() < length) {
            subfulfillments.add(readFulfillment(in, subfulfillmentsBytesRead));
          }
          innerBytesRead.addAndGet(subfulfillmentsBytesRead.get());
          
          tag = in.readTag(1, innerBytesRead, DERTags.CONSTRUCTED, DERTags.TAGGED);
          length = in.readLength(innerBytesRead);

        } else if (tag != 1) {
          throw new DEREncodingException("Expected tag: 1, got: " + tag);
        }

        List<Condition> subconditions = new ArrayList<>();

        AtomicInteger subconditionsBytesRead = new AtomicInteger();
        while (subconditionsBytesRead.get() < length) {
          subconditions.add(readCondition(in, subconditionsBytesRead));
        }
        innerBytesRead.addAndGet(subconditionsBytesRead.get());

        bytesRead.addAndGet(innerBytesRead.get());

        return new ThresholdSha256Fulfillment(
            subconditions.toArray(new Condition[subconditions.size()]),
            subfulfillments.toArray(new Fulfillment[subfulfillments.size()]));

      case RSA_SHA256:

        BigInteger modulus = new BigInteger(
            in.readTaggedObject(0, length - innerBytesRead.get(), innerBytesRead).getValue());
        byte[] rsaSignature =
            in.readTaggedObject(1, length - innerBytesRead.get(), innerBytesRead).getValue();

        bytesRead.addAndGet(innerBytesRead.get());
        
        RSAPublicKeySpec rsaSpec = new RSAPublicKeySpec(modulus, BigInteger.valueOf(65534));

        try {
          KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");
          PublicKey publicKey = rsaKeyFactory.generatePublic(rsaSpec);

          return new RsaSha256Fulfillment((RSAPublicKey) publicKey, rsaSignature);

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
          throw new RuntimeException("Error creating RSA key.", e);
        }
        

      case ED25519_SHA256:
        byte[] ed25519key =
            in.readTaggedObject(0, length - innerBytesRead.get(), innerBytesRead).getValue();
        byte[] ed25519Signature =
            in.readTaggedObject(1, length - innerBytesRead.get(), innerBytesRead).getValue();

        bytesRead.addAndGet(innerBytesRead.get());

        EdDSAPublicKeySpec ed25519spec = new EdDSAPublicKeySpec(ed25519key,
            EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.CURVE_ED25519_SHA512));
        EdDSAPublicKey ed25519PublicKey = new EdDSAPublicKey(ed25519spec);

        return new Ed25519Sha256Fulfillment(ed25519PublicKey, ed25519Signature);
    }

    throw new DEREncodingException("Unrecogized tag: " + tag);

  }
}

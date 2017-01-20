package org.interledger.cryptoconditions;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.net.URI;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.interledger.cryptoconditions.der.DEROutputStream;
import org.interledger.cryptoconditions.der.DERTags;
import org.interledger.cryptoconditions.uri.CryptoConditionUri;
import org.interledger.cryptoconditions.uri.NamedInformationUri;
import org.interledger.cryptoconditions.uri.NamedInformationUri.HashFunction;

/**
 * The ConditionBase class provides shared logic for 
 * conditions. 
 * 
 * It provides concrete implementations of {@link #getCost()},
 * {@link #getEncoded()}, {@link #getUri()}, {@link #equals(Object)},
 * {@link #hashCode()} and {@link #toString()}.
 * 
 * @author adrianhopebailie
 *
 */
public abstract class ConditionBase implements Condition {

  private long cost;
  private URI uri;
  private byte[] encoded;
  
  /**
   * Default internal constructor for all conditions.
   * 
   * Sub-classes must statically calculate the cost of a
   * condition and call this constructor with the correct
   * cost value.
   * 
   * @param cost the cost value for this condition.
   */
  protected ConditionBase(long cost) {
    this.cost = cost;
  }

  @Override
  public long getCost() {
    return cost;
  }
  
  /**
   * Generates and caches the DER encoded condition on first call.
   * 
   * Returns a copy of the internally cached byte array.
   * 
   */
  @Override
  public byte[] getEncoded() {
    
    if(encoded == null) {
      try {
        // Build Fingerprint and Cost SEQUENCE
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(baos);
        out.writeTaggedObject(0, getFingerprint());
        out.writeTaggedObject(1, BigInteger.valueOf(getCost()).toByteArray());
        if (this instanceof CompoundCondition) {
          byte[] bitStringData =
              ConditionType.getEnumOfTypesAsBitString(((CompoundCondition) this).getSubtypes());
          out.writeTaggedObject(2, bitStringData);
        }
        out.close();
        byte[] buffer = baos.toByteArray();

        // Wrap CHOICE
        baos = new ByteArrayOutputStream();
        out = new DEROutputStream(baos);
        out.writeEncoded(
            DERTags.CONSTRUCTED.getTag() + DERTags.TAGGED.getTag() + getType().getTypeCode(), buffer);
        out.close();
        return baos.toByteArray();
      } catch (IOException e) {
        throw new UncheckedIOException("DER Encoding Error.", e);
      }
    }
    
    byte[] returnVal = new byte[encoded.length];
    System.arraycopy(encoded, 0, returnVal, 0, encoded.length);
    
    return returnVal;
  }

  @Override
  public URI getUri() {
    
    if(uri == null) {
      
      Map<String, String> params = new HashMap<>();
      params.put(CryptoConditionUri.QueryParams.TYPE, getType().toString().toLowerCase());
      params.put(CryptoConditionUri.QueryParams.COST, Long.toString(getCost()));
      
      if (this instanceof CompoundCondition) {
        CompoundCondition cc = (CompoundCondition)this;
        if (cc.getSubtypes() != null && !cc.getSubtypes().isEmpty()) {
          params.put(CryptoConditionUri.QueryParams.SUBTYPES, ConditionType.getEnumOfTypesAsString(cc.getSubtypes()));
        }
      }
      
      uri = NamedInformationUri.getUri(HashFunction.SHA_256, getFingerprint(), params);
      
    }
    
    return uri;
    
  }
  

  /**
   * Overrides the default {@link java.lang.Object#hashCode()} to
   * generate the hashCode from the type and fingerprint.
   */
  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    int typeCode = getType().getTypeCode();
    result = prime * result + (int) (typeCode ^ (typeCode >>> 32));
    result = prime * result + Arrays.hashCode(getEncoded());
    return result;
  }

  /**
   * Overrides the default {@link java.lang.Object#equals(Object)} to
   * compare the type and fingerprint.
   */
  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (!(obj instanceof Condition))
      return false;
    
    Condition other = (Condition) obj;
    if (getType() != other.getType())
      return false;
    if (getCost() != other.getCost())
      return false;
    if (!Arrays.equals(getFingerprint(), other.getFingerprint()))
      return false;
    
    return true;
  }
  
  /**
   * Overrides the default {@link java.lang.Object#toString()} and 
   * returns the result of {@link #getUri()} as a string.
   * 
   */
  @Override
  public String toString() {
    return getUri().toString();
  }

}

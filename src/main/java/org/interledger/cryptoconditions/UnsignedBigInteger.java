package org.interledger.cryptoconditions;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Utility class for encoding and decoding a {@link BigInteger}
 * as a {@link byte[]} without sign prefix.
 * 
 * @author adrianhopebailie
 *
 */
public class UnsignedBigInteger {

  /**
   * Get a positive {@link BigInteger} encoded as a {@link byte[]} with no sign-prefix.
   * 
   * @param value a positive BigInteger value
   * @return input value encoded as a byte[] with leading 0x00 prefix trimmed.
   * @throws IllegalArgumentException if the input value is <0
   */
  public static byte[] toUnsignedByteArray(BigInteger value) {

    if (value.signum() < 0) {
      throw new IllegalArgumentException("value must be a positive BigInteger");
    }

    byte[] signedValue = value.toByteArray();
    if (signedValue[0] == 0x00) {
      Arrays.copyOfRange(signedValue, 1, signedValue.length);
    }

    return signedValue;
  }

  /**
   * Get {@link BigInteger} from byte encoding that assumes the value is >0.
   * 
   * Same as calling {@code new BigInteger(1, value);}.
   * 
   * @param value a byte encoded integer
   * @return a positive {@link BigInteger}
   */
  public static BigInteger fromUnsignedByteArray(byte[] value) {
    return new BigInteger(1, value);
  }

}

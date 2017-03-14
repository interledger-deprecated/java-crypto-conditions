package org.interledger.cryptoconditions.der;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;

/**
 * An output stream for writing DER encoded data.
 */
public class DerOutputStream extends FilterOutputStream {

  public DerOutputStream(OutputStream out) {
    super(out);
  }

  /**
   * Writes the DER tag to the stream.
   * 
   * @param tag The tag to write.
   * @param index The index of the tag.
   */
  public void writeTag(DerTag tag, int index) throws IOException {
    write(tag.getTag() + index);
  }

  /**
   * Writes a DER encoded length indicator to the stream.
   * 
   * @param length The length value to write to the stream.
   */
  public void writeLength(int length) throws IOException {
    if (length > 127) {
      int size = 1;
      int val = length;

      while ((val >>>= 8) != 0) {
        size++;
      }

      write((byte) (size | 0x80));

      for (int i = (size - 1) * 8; i >= 0; i -= 8) {
        write((byte) (length >> i));
      }
    } else {
      write((byte) length);
    }
  }

  /**
   * Writes an encoded DER value to the stream.
   * 
   * @param tag The DER tag that should accompany the value.
   * @param bytes The value to write to the stream.
   */
  public void writeEncoded(int tag, byte[] bytes) throws IOException {
    write(tag);
    writeLength(bytes.length);
    write(bytes);
  }

  /**
   * Writes the value as a DER integer to the steam.
   * 
   * @param value The value to write to the stream.
   */
  public void writeInteger(BigInteger value) throws IOException {
    writeEncoded(DerTag.INTEGER.getTag(), value.toByteArray());
  }

  /**
   * Writes the value as a DER octet string to the stream.
   * 
   * @param octets The octets to write to the stream.
   */
  public void writeOctetString(byte[] octets) throws IOException {
    writeEncoded(DerTag.OCTET_STRING.getTag(), octets);
  }

  /**
   * Writes the value as a DER tagged object.
   * 
   * @param tagNumber The tag number for the object.
   * @param object The value to write to the stream.
   */
  public void writeTaggedObject(int tagNumber, byte[] object) throws IOException {
    writeEncoded(DerTag.TAGGED.getTag() + tagNumber, object);
  }

  /**
   * Writes the value as a DER tagged, constructed object.
   * 
   * @param tagNumber The tag number for the object.
   * @param object The value to write to the stream.
   */
  public void writeTaggedConstructedObject(int tagNumber, byte[] object) throws IOException {
    writeEncoded(DerTag.TAGGED.getTag() + DerTag.CONSTRUCTED.getTag() + tagNumber, object);
  }

  /**
   * Writes the value as a DER bit string.
   * 
   * @param bitStringData The bit string value to write to the stream.
   */
  public void writeBitString(byte[] bitStringData) throws IOException {
    writeEncoded(DerTag.BIT_STRING.getTag(), bitStringData);
  }

  /**
   * TODO: confirm if this method should be implemented...
   * @param bitString The bit string value to write to the stream.
   * @param unusedBits  Indicates the number of unused bits in the bit string.
   */
  public void writeBitString(byte[] bitString, int unusedBits) {
    // TODO: this method doesnt do anything?
    byte[] bytes = new byte[bitString.length + 1];

    bytes[0] = (byte) unusedBits;
    System.arraycopy(bitString, 0, bytes, 1, bytes.length - 1);

  }
}

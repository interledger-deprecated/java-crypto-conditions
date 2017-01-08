package org.interledger.cryptoconditions.der;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;

public class DEROutputStream extends FilterOutputStream {

  public DEROutputStream(OutputStream out) {
    super(out);
  }

  public void writeTag(DERTags tag, int index) throws IOException {
    write(tag.getTag() + index);
  }

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

  public void writeEncoded(int tag, byte[] bytes) throws IOException {
    write(tag);
    writeLength(bytes.length);
    write(bytes);
  }

  public void writeInteger(BigInteger value) throws IOException {
    writeEncoded(DERTags.INTEGER.getTag(), value.toByteArray());
  }

  public void writeOctetString(byte[] octets) throws IOException {
    writeEncoded(DERTags.OCTET_STRING.getTag(), octets);
  }

  public void writeTaggedObject(int tagNumber, byte[] object) throws IOException {
    writeEncoded(DERTags.TAGGED.getTag() + tagNumber, object);
  }

  public void writeTaggedConstructedObject(int tagNumber, byte[] object) throws IOException {
    writeEncoded(DERTags.TAGGED.getTag() + DERTags.CONSTRUCTED.getTag() + tagNumber, object);
  }

  public void writeBitString(byte[] bitStringData) throws IOException {
    writeEncoded(DERTags.BIT_STRING.getTag(), bitStringData);
  }

  public void writeBitString(byte[] bitString, int unusedBits) {
    byte[] bytes = new byte[bitString.length + 1];

    bytes[0] = (byte) unusedBits;
    System.arraycopy(bitString, 0, bytes, 1, bytes.length - 1);

  }



}

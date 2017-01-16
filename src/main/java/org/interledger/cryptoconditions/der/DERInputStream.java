package org.interledger.cryptoconditions.der;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.atomic.AtomicInteger;

public class DERInputStream extends FilterInputStream {

  public DERInputStream(InputStream in) {
    super(in);
  }

  public DERObject readTaggedConstructedObject(int expectedTagNumber, int limit, AtomicInteger bytesRead) throws IOException, DEREncodingException {
  
    DERObject object = readObject(limit, bytesRead);
    if(object.getTag() != (DERTags.TAGGED.getTag() + DERTags.CONSTRUCTED.getTag() + expectedTagNumber)) {
      throw new DEREncodingException("Expected tag: " + DERTags.TAGGED.getTag() + DERTags.CONSTRUCTED.getTag() + expectedTagNumber + 
          " but got: " + object.getTag());
    }
    
    return object;
  }
   
  public DERObject readTaggedObject(int expectedTagNumber, int limit, AtomicInteger bytesRead) throws IOException, DEREncodingException {

    DERObject object = readObject(limit, bytesRead);
    if(object.getTag() != (DERTags.TAGGED.getTag() + expectedTagNumber)) {
      throw new DEREncodingException("Expected tag: " + Integer.toHexString(DERTags.TAGGED.getTag() + expectedTagNumber) + 
          " but got: " + Integer.toHexString(object.getTag()));
    }
    return object;
    
  }
  
  public DERObject readObject(int limit, AtomicInteger bytesRead) throws IOException, DEREncodingException {
    
    AtomicInteger innerBytesRead = new AtomicInteger(0);
    DERObject obj = new DERObject();
    obj.setTag(readTag(innerBytesRead));
    obj.setLength(readLength(innerBytesRead));
    if(innerBytesRead.get() + obj.getLength() > limit) {
      throw new DEREncodingException("Object length [" + obj.getLength() + "] is larger than allowed.");
    }
    bytesRead.addAndGet(innerBytesRead.get());
    
    if(obj.getLength() > 0) {
      obj.setValue(readValue(obj.getLength(), bytesRead));
    } else {
      obj.setValue(new byte[]{});
    }
    return obj;
  }

  public int readTag(int expectedTag, AtomicInteger bytesRead, DERTags... flags) throws DEREncodingException, IOException {
    int tag = readTag(bytesRead, flags);
    
    if(tag != expectedTag) {
      throw new DEREncodingException("Expected tag: " + Integer.toHexString(expectedTag) + ", got: " + Integer.toHexString(tag));
    }
    return tag;
  }
    
  public int readTag(AtomicInteger bytesRead, DERTags... expectedFlags) throws DEREncodingException, IOException {

    int tag = in.read();
    bytesRead.incrementAndGet();
    
    if(tag < 0) {
      throw new DEREncodingException("Expected tag, got end of stream.");
    }

    for (DERTags DERTag : expectedFlags) {
      tag -= DERTag.getTag();
    }
    
    if(tag < 0) {
      throw new DEREncodingException("Some flags are missing resulting in a tag value of < 0.");
    }
    
    return tag;
  }
  
  public int readLength(AtomicInteger bytesRead) throws DEREncodingException, IOException {
    
    int lengthOfLength = 1;
    int length = in.read();
    bytesRead.incrementAndGet();
    
    if (length > 127) {
      lengthOfLength = length & 0x7f;
      if (lengthOfLength > 4)
      {
          throw new DEREncodingException("DER length more than 4 bytes: " + lengthOfLength);
      }
      length = 0;
      for (int i = 0; i < lengthOfLength; i++)
      {
          int next = in.read();
          bytesRead.incrementAndGet();
          if (next < 0)
          {
              throw new DEREncodingException("End of stream found reading length.");
          }

          length = (length << 8) + next;
      }
      if (length < 0)
      {
          throw new DEREncodingException("Negative length found: " + length);
      }
    }
    
    return length;
    
  }
  
  
  public byte[] readValue(int length, AtomicInteger bytesRead) throws IOException, DEREncodingException {
    
    byte[] buffer = new byte[length];
    if (in.read(buffer, 0, length) < length)
    {
        throw new DEREncodingException("End of stream found reading value.");
    }
    bytesRead.addAndGet(length);
    
    return buffer;
  }
}

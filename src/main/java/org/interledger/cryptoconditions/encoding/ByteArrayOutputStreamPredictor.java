package org.interledger.cryptoconditions.encoding;

import java.io.IOException;
import java.io.ByteArrayOutputStream;

public class ByteArrayOutputStreamPredictor extends ByteArrayOutputStream {

    public ByteArrayOutputStreamPredictor() {
        // Do nothing
    }

    public ByteArrayOutputStreamPredictor(int count) {
        // Do nothing
    }

    @Override
    public void write(int b) {
        count++;
    }
    
    @Override
    public void write(byte b[]) throws IOException {
        count += b.length;
    }
    
    @Override
    public void write(byte b[], int off, int len) {
        count += len;
    }
    
    @Override
    public void flush() throws IOException {
        count = 0;
    }
    
    
}

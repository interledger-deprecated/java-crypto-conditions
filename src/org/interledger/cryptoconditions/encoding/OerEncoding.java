package org.interledger.cryptoconditions.encoding;

import java.io.IOException;
import java.io.OutputStream;

public class OerEncoding {
	
	public static void writeOerEncodedBoundedUnsignedInteger(OutputStream stream, int value, int upperBound) 
			throws IOException {
		
		if(upperBound <= 255) {
			stream.write(value);
		} else if (upperBound <= 65535) {
			stream.write((value >> 8));
			stream.write(value);
		} else {
			stream.write((value >> 24));
			stream.write((value >> 16));
			stream.write((value >> 8));
			stream.write(value);
		}		
	}
}

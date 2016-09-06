package org.interledger.cryptoconditions.encoding;

import java.io.EOFException;

import java.io.IOException;
import java.io.InputStream;

import org.interledger.cryptoconditions.UnsupportedLengthException;

/**
 * OER input stream reads OER encoded data from an underlying stream
 *
 * Limitations - INTEGER types are only supported up to 3 bytes (UNSIGNED)
 *
 * @author adrianhopebailie
 *
 */
public class OerInputStream extends InputStream {

    protected final InputStream stream;

    public OerInputStream(InputStream stream) {
        this.stream = stream;
    }

    public int read8BitUInt() throws IOException {
        int value = stream.read();
        verifyNotEOF(value);
        return value;
    }

    public int read16BitUInt() throws IOException {

        int value = stream.read();
        verifyNotEOF(value);
        int next = stream.read();
        verifyNotEOF(next);

        return next + (value << 8);
    }

    public int readVarUInt() throws IOException, UnsupportedLengthException, IllegalLengthIndicatorException {

        // We only support a 3 byte length indicator otherwise we go beyond
        // Integer.MAX_SIZE
        int length = readLengthIndicator();
        int value = stream.read();
        verifyNotEOF(value);

        if (length == 1) {
            return value;
        } else if (length == 2) {
            int next = stream.read();
            verifyNotEOF(next);
            return value + (next << 8);
        } else if (length == 3) {
            int next = stream.read();
            verifyNotEOF(next);
            value += (next << 8);
            next = stream.read();
            verifyNotEOF(next);
            return value + (next << 16);
        } else {
            throw new IllegalArgumentException("Integers of greater than 16777215 (3 bytes) are not supported.");
        }

    }

    public byte[] readOctetString() throws IOException, UnsupportedLengthException, IllegalLengthIndicatorException {
        int length = readLengthIndicator();
        if (length == 0) {
            return new byte[]{};
        }
        byte[] value = new byte[length];
        int bytesRead = 0;
        bytesRead = stream.read(value, 0, length);
        if (bytesRead < length) {
            throw new EOFException("Unexpected EOF when trying to decode OER data.");
        }
        return value;
    }

    @Override
    public int read() throws IOException {
        return this.stream.read();
    }

    protected int readLengthIndicator()
            throws IOException, UnsupportedLengthException, IllegalLengthIndicatorException {
        int length = stream.read();

        verifyNotEOF(length);

        if (length < 128) {
            return length;
        } else if (length > 128) {
            int lengthOfLength = length - 127;
            if (lengthOfLength > 3) {
                throw new UnsupportedLengthException("This implementation only supports "
                        + "variable length fields up to 16777215 bytes.");
            }

            length = 0;
            for (int i = 1; i <= lengthOfLength; i++) {
                int next = stream.read();
                verifyNotEOF(next);
                length += (next << (8 * (length - i)));
            }
            return length;
        } else {
            throw new IllegalLengthIndicatorException("First byte of length indicator can't be 0x80.");
        }
    }

    protected void verifyNotEOF(int data) throws EOFException {
        if (data == -1) {
            throw new EOFException("Unexpected EOF when trying to decode OER data.");
        }
    }

}

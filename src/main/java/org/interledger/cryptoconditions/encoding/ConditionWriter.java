package org.interledger.cryptoconditions.encoding;

import java.io.IOException;
import java.io.Writer;
import java.util.EnumSet;

import org.interledger.cryptoconditions.Condition;
import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.FeatureSuite;

public class ConditionWriter extends Writer {

    private static char[] HEADER = new char[]{'c', 'c'};
    private static char[] VERSION = new char[]{'0', '1'};
    private static char DELIMITER = ':';
    
    private Writer writer;
    
    public ConditionWriter(Writer innerWriter) {
        this.writer = innerWriter;
    }
    
    /**
     * Write the condition to the underlying writer using String encoding
     * 
     * @param condition
     * @throws IOException
     */
    public void writeCondition(Condition condition) throws IOException
    {
        writeHeader();
        writeDelimiter();
        writeVersion();
        writeDelimiter();
        writeConditionType(condition.getType());
        writeDelimiter();
        writeFeatures(condition.getFeatures());
        writeDelimiter();
        writeFingerprint(condition.getFingerprint());
        writeDelimiter();
        writeMaxFulfillmentLength(condition.getMaxFulfillmentLength());
        
    }
    
    protected void writeDelimiter()
            throws IOException
    {
        writer.write(DELIMITER);
    }
    
    protected void writeHeader() 
            throws IOException
    {
        writer.write(HEADER);
    }

    protected void writeVersion() 
            throws IOException
    {
        writer.write(VERSION);
    }

    protected void writeConditionType(ConditionType type) 
            throws IOException 
    {
        writer.write(Integer.toString(type.getTypeCode(), 16));
    }
    

    protected void writeFeatures(EnumSet<FeatureSuite> features) 
            throws IOException {
        
        //TODO - This is easy to read but could probably be optimized
        int encoded_bitmask = 0;
        for (FeatureSuite featureSuite : features) {
            encoded_bitmask += featureSuite.toInt();
        }
        
        writer.write(Integer.toString(encoded_bitmask, 16));        
    }
    
    protected void writeFingerprint(byte[] fingerprint) 
            throws IOException {
        
        writer.write(Base64Url.encode(fingerprint));
    }

    protected void writeMaxFulfillmentLength(int maxFulfillmentLength) 
            throws IOException {
        
        writer.write(Integer.toString(maxFulfillmentLength));
    }
    
    
    @Override
    public void write(char[] cbuf, int off, int len) throws IOException {
        writer.write(cbuf, off, len);
    }

    @Override
    public void flush() throws IOException {
        writer.flush();
    }

    @Override
    public void close() throws IOException {
        writer.close();
    }

}

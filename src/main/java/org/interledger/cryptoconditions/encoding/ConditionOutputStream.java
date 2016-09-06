package org.interledger.cryptoconditions.encoding;

import java.io.IOException;
import java.io.OutputStream;
import java.util.EnumSet;

import org.interledger.cryptoconditions.Condition;
import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.FeatureSuite;

/**
 * Writes an OER encoded condition to a stream.
 * 
 * Limitations:
 * - Only supports the compiled condition type codes (up to 4)
 * - Only supports a feature bitmask of 1 byte in length
 * - Assumes fingerprint length of less than 16777215 bytes
 * - Only accepts a MaxFulfillmentLength of 16777215 or less
 * 
 * @author adrianhopebailie
 */
public class ConditionOutputStream extends OerOutputStream {
            
    public ConditionOutputStream(OutputStream stream)
    {
        super(stream);
    }
    
    /**
     * Write the condition to the underlying stream using OER encoding
     * per the specification:
     * 
     * Condition ::= SEQUENCE {
     *     type ConditionType,
     *     featureBitmask OCTET STRING,
     *     fingerprint OCTET STRING,
     *     maxFulfillmentLength INTEGER (0..MAX)
     * }
     * 
     * ConditionType ::= INTEGER {
     *     preimageSha256(0),
     *     rsaSha256(1),
     *     prefixSha256(2),
     *     thresholdSha256(3),
     *     ed25519(4)
     * } (0..65535)
     * 
     * @param condition
     * @throws IOException
     */
    public void writeCondition(Condition condition) throws IOException
    {
        writeConditionType(condition.getType());
        writeFeatures(condition.getFeatures());
        writeFingerprint(condition.getFingerprint());
        writeMaxFulfillmentLength(condition.getMaxFulfillmentLength());
        
    }

    protected void writeConditionType(ConditionType type) 
            throws IOException
    {
        write16BitUInt(type.getTypeCode());
    }
    

    protected void writeFeatures(EnumSet<FeatureSuite> features) 
            throws IOException {
        
        //TODO - Unsafe if we overflow into a second byte
        
        int encoded_bitmask = 0;
        for (FeatureSuite featureSuite : features) {
            encoded_bitmask += featureSuite.toInt();
        }
        writeLengthIndicator(1);
        stream.write(encoded_bitmask);
        
    }
    
    protected void writeFingerprint(byte[] fingerprint) 
            throws IOException {
        writeOctetString(fingerprint);            
    }

    protected void writeMaxFulfillmentLength(int maxFulfillmentLength) 
            throws IOException {
        writeVarUInt(maxFulfillmentLength);
    }
    
}

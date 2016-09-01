package org.interledger.cryptoconditions.encoding;

import java.io.IOException;
import java.io.InputStream;
import java.util.EnumSet;

import org.interledger.cryptoconditions.Condition;
import org.interledger.cryptoconditions.ConditionImpl;
import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.FeatureSuite;
import org.interledger.cryptoconditions.UnsupportedConditionException;
import org.interledger.cryptoconditions.UnsupportedFeaturesException;
import org.interledger.cryptoconditions.UnsupportedLengthException;

/**
 * Reads and decodes Conditions from an underlying input stream.
 * 
 * Conditions are expected to be OER encoded on the stream
 * 
 * @see Condition
 * @author adrianhopebailie
 *
 */
public class ConditionInputStream extends OerInputStream {
    
    public ConditionInputStream(InputStream stream) {
        super(stream);
    }
    
    /**
     * Read a condition from the underlying stream using OER encoding
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
     * @throws OerDecodingException
     * @throws IOException
     * @throws UnsupportedConditionException
     */
    public Condition readCondition()
            throws IOException, UnsupportedConditionException, OerDecodingException 
    {
        final ConditionType type = readConditiontype();
        final EnumSet<FeatureSuite> features = readFeatures();
        final byte[] fingerprint = readFingerprint();
        final int maxFulfillmentValue = readMaxFullfilmentValue();
        return new ConditionImpl(type, features, fingerprint, maxFulfillmentValue);

    }
    
    protected ConditionType readConditiontype() 
            throws IOException {
        int value = read16BitUInt();
        return ConditionType.valueOf(value);
    }

    protected EnumSet<FeatureSuite> readFeatures() 
            throws IOException, UnsupportedFeaturesException, UnsupportedLengthException, IllegalLengthIndicatorException {
        
            byte[] bitmask_bytes = readOctetString();
            if(bitmask_bytes.length > 1) {
                //We currently only support a bitmask of 1 byte
                throw new UnsupportedFeaturesException("Unknown feature bits encountered.");
            }
            
            EnumSet<FeatureSuite> features = EnumSet.noneOf(FeatureSuite.class);
            for (FeatureSuite featureSuite : FeatureSuite.values()) {
                if((featureSuite.toInt() & bitmask_bytes[0]) == featureSuite.toInt())
                {
                    features.add(featureSuite);
                    
                    //Unset the bit so we can check we processed them all
                    bitmask_bytes[0] &= ~featureSuite.toInt();
                }
            }
            
            if(bitmask_bytes[0] != 0x00) {
                throw new UnsupportedFeaturesException("Unknown feature bits encountered.");
            }
            
            return features;        
    }

    protected byte[] readFingerprint() 
            throws IOException, UnsupportedLengthException, IllegalLengthIndicatorException {
        
        return readOctetString();
    }
    
    private int readMaxFullfilmentValue() 
            throws UnsupportedConditionException, IOException, IllegalLengthIndicatorException {
        return readVarUInt();
    }
    
}

package org.interledger.cryptoconditions;

import java.util.EnumSet;

import org.interledger.cryptoconditions.util.Crypto;
import org.interledger.cryptoconditions.types.*;

/**
 * Implementation of a PREIMAGE-SHA-256 crypto-condition fulfillment
 * 
 * TODO Safe synchronized access to members?
 * 
 * @author adrianhopebailie
 *
 */
public class PreimageSha256Fulfillment extends FulfillmentBase {

    private byte[] preimage;
    public static PreimageSha256Fulfillment BuildFromSecrets(byte[] preimage){
        FulfillmentPayload payload = new FulfillmentPayload(preimage);
        PreimageSha256Fulfillment result = new PreimageSha256Fulfillment(ConditionType.PREIMAGE_SHA256, payload);
        result.setPreimage(preimage);
        return result;
    }

    private void setPreimage(byte[] preimage){
        this.preimage = preimage;
    }

    public PreimageSha256Fulfillment(ConditionType type, FulfillmentPayload payload) {
        super(type, payload);
        this.preimage = payload.payload;
    }

    private static final EnumSet<FeatureSuite> BASE_FEATURES = EnumSet.of(
            FeatureSuite.SHA_256,
            FeatureSuite.PREIMAGE
        );

//    public byte[] getPreimage() {
//        byte[] result = Arrays.copyOf(payload.payload, payload.payload.length);
//        return result;
//    }
    
    @Override
    public ConditionType getType() {
        return ConditionType.PREIMAGE_SHA256;
    }

    @Override
    public Condition generateCondition() {
        if (preimage == null ) {
            throw new RuntimeException("preimage not initialized");
        }
        byte[] fingerprint = Crypto.getSha256Hash(preimage);
        int maxFulfillmentLength = preimage.length; // TODO:(0) Recheck
        Condition result = new ConditionImpl(
                ConditionType.PREIMAGE_SHA256, 
                BASE_FEATURES, 
                fingerprint, 
                maxFulfillmentLength);
        return result;
    }
    

    /**
     * Validate this fulfillment.
     *
     * Copy&Paste from five-bells-condition/src/types/preimage-sha256.js:
     * """
     * For a SHA256 hashlock fulfillment, successful parsing implies that the
     * fulfillment is valid, so this method is a no-op.
     * """
     *
     * @param {byte[]} Message (ignored in this condition type)
     * @return {boolean} Validation result
     */
    @Override
    public boolean validate(MessagePayload message) {
        // TODO:(0) recheck
        // TODO:(0) Create unit tests.
        return true;
    }
}

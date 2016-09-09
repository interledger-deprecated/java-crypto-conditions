package org.interledger.cryptoconditions;

import java.io.ByteArrayOutputStream;
import java.util.EnumSet;

import org.interledger.cryptoconditions.types.*;

import org.interledger.cryptoconditions.encoding.Base64Url;
import org.interledger.cryptoconditions.encoding.FulfillmentOutputStream;

public abstract class FulfillmentBase implements Fulfillment {

    protected FulfillmentPayload payload;
    /*
     *  condition can't be declared final since it can't be initialized
     *  in the constructor. Nevertheless, we can force to init it in generateCondition
     *  by passing only final immutable parameters as input.
     */
    private Condition condition;

    /*
     * Default constructor. Raise exception to force use of child classes.
     */
    FulfillmentBase() {
//        throw new RuntimeException("Use a child class constructor");
    }

    /*
     * Create from URI-encoded string
     */
    public FulfillmentBase(ConditionType type, FulfillmentPayload payload) {
        this.payload = payload;
        if (!type.equals(this.getType())) {
            throw new RuntimeException("Implementation error. Type mismatch. "
                    + "Expected " + this.getType() + " but URI indicates " + type.toString());
        }
        // Can't generateCondition -> Derived classes must initialize internal members first
        //   but the Java syntax force to call parent constructor before "anything else".
        //
        // this.condition = this.generateCondition(payload);
    }

    final public Condition getCondition() {
        if (condition == null) {
            condition = generateCondition();
        }
        return condition;
    }

    @Override
    public ConditionType getType() {
        throw new RuntimeException("getType called in abstract parent class FulfillmentBase");
    }

    @Override
    final public FulfillmentPayload getPayload() {
        if (this.payload == null) {
            throw new RuntimeException("Payload not YET initialized");
        }

        return this.payload;
    }

    @Override
    final public EnumSet<FeatureSuite> getFeatures() {
        if (this.condition == null) {
            this.condition = this.generateCondition();
        }
        return this.condition.getFeatures();
    }

    @Override
    final public String toURI() {
        return "cf"
                + ":" + Integer.toHexString(this.getType().getTypeCode())
                + ":" + Base64Url.encode(this.getPayload().payload);
    }

    @Override
    final public String toString() {
        return toURI();
    }

    @Override
    final public byte[] serializeBinary () {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        FulfillmentOutputStream oos = new FulfillmentOutputStream(os);
        try{
            oos.write16BitUInt(this.getType().getTypeCode());
            oos.writeOctetString(this.payload.payload);
            byte[] result = os.toByteArray();
            return result;
        }catch(Exception e) {
            throw new RuntimeException(e.toString(), e);
        } finally {
            oos.close();
        }
      }
}

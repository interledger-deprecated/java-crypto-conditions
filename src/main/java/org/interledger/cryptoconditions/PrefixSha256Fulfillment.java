package org.interledger.cryptoconditions;

import java.io.ByteArrayOutputStream;

import java.io.IOException;
import java.util.EnumSet;

import org.interledger.cryptoconditions.encoding.ConditionOutputStream;
import org.interledger.cryptoconditions.encoding.FulfillmentOutputStream;
import org.interledger.cryptoconditions.util.Crypto;
import org.interledger.cryptoconditions.types.*;

/**
 * Implementation of a PREFIX-SHA-256 crypto-condition fulfillment
 *
 * TODO Safe synchronized access to members?
 *
 * @author adrianhopebailie
 *
 */
public class PrefixSha256Fulfillment extends FulfillmentBase {

    private static EnumSet<FeatureSuite> BASE_FEATURES = EnumSet.of(
            FeatureSuite.SHA_256,
            FeatureSuite.PREFIX
    );

    private final byte[] prefix; // TODO:(0) Wrap into PrefixPayload?
    private final Fulfillment subfulfillment;

    public PrefixSha256Fulfillment(ConditionType type, FulfillmentPayload payload, byte[] prefix, Fulfillment subfulfillment) {
        super(type, payload);
        this.prefix = prefix;
        this.subfulfillment = subfulfillment;
    }

    /*
     * Make private and use static constructor BuildFromParams. 
     * That hide many Java specific details with variable scope and makes 
     * it easy to port to other languages.
     */
    private PrefixSha256Fulfillment(byte[] prefix, Fulfillment subfulfillment) {
        this.prefix = prefix.clone();
        this.subfulfillment = subfulfillment;

        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        FulfillmentOutputStream ffOutputStream = new FulfillmentOutputStream(byteStream);
        try {
            ffOutputStream.writeOctetString(prefix);
            ffOutputStream.writeFulfillment(subfulfillment);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } finally {
            ffOutputStream.close();
        }
        this.payload = new FulfillmentPayload(byteStream.toByteArray());
//        PrefixSha256Fulfillment result = 
    }

    // TODO:(0) In the JS implementation there is also a Constructor (prefix, subcondition)
    public static PrefixSha256Fulfillment BuildFromParams(byte[] prefix, Fulfillment subfulfillment) {
        PrefixSha256Fulfillment result = new PrefixSha256Fulfillment(prefix, subfulfillment);
        return result;
    }

    public byte[] getPrefix() {
        return prefix.clone();
    }

    public Fulfillment getSubFulfillment() {
        return subfulfillment;
    }

    @Override
    public ConditionType getType() {
        return ConditionType.PREFIX_SHA256;
    }

    @Override
    public Condition generateCondition() {
        Condition subcondition = subfulfillment.generateCondition();

        EnumSet<FeatureSuite> features = subcondition.getFeatures();
        features.addAll(BASE_FEATURES);

        byte[] fingerprint = Crypto.getSha256Hash(
                calculateFingerPrintContent(
                        prefix,
                        subcondition
                )
        );

        int maxFulfillmentLength = calculateMaxFulfillmentLength(
                prefix,
                subcondition
        );

        return new ConditionImpl(
                ConditionType.PREFIX_SHA256,
                features,
                fingerprint,
                maxFulfillmentLength);
    }

    protected byte[] calculatePayload() {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        FulfillmentOutputStream stream = new FulfillmentOutputStream(buffer);

        try {
            stream.writeOctetString(prefix);
            stream.writeFulfillment(subfulfillment);
            stream.flush();
            return buffer.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        } finally {
            stream.close();
        }
    }

    private byte[] calculateFingerPrintContent(byte[] prefix, Condition subcondition) {

        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        ConditionOutputStream stream = new ConditionOutputStream(buffer);

        try {
            stream.writeOctetString(prefix);
            stream.writeCondition(subcondition);
            stream.flush();
            return buffer.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        } finally {
            stream.close();
        }
    }

    private int calculateMaxFulfillmentLength(byte[] prefix, Condition subcondition) {
        int length = prefix.length;
        if (length < 128) {
            length = length + 1;
        } else if (length <= 255) {
            length = length + 2;
        } else if (length <= 65535) {
            length = length + 3;
        } else if (length <= 16777215) {
            length = length + 4;
        } else {
            throw new IllegalArgumentException("Field lengths of greater than 16777215 are not supported.");
        }
        return length + subcondition.getMaxFulfillmentLength();
    }

    @Override
    public boolean validate(MessagePayload message) {
        if (this.subfulfillment == null) {
            throw new RuntimeException("subfulfillment not yet initialized ");
        }
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            outputStream.write(this.prefix);
            outputStream.write(message.payload);
        } catch (IOException e) {
            throw new RuntimeException(e.toString());
        }

        return this.subfulfillment.validate(new MessagePayload(outputStream.toByteArray()));
    }
}

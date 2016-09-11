package org.interledger.cryptoconditions.encoding;

import java.io.ByteArrayInputStream;


import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;

import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.Fulfillment;
import org.interledger.cryptoconditions.PrefixSha256Fulfillment;
import org.interledger.cryptoconditions.PreimageSha256Fulfillment;
import org.interledger.cryptoconditions.Ed25519Fulfillment;
import org.interledger.cryptoconditions.RsaSha256Fulfillment;
import org.interledger.cryptoconditions.ThresholdSHA256Fulfillment;
import org.interledger.cryptoconditions.UnsupportedConditionException;
import org.interledger.cryptoconditions.UnsupportedLengthException;

import org.interledger.cryptoconditions.types.*;

/**
 * Reads and decodes Fulfillments from an underlying input stream.
 *
 * Fulfillments are expected to be OER encoded on the stream
 *
 * @see Fulfillment
 * @author adrianhopebailie
 *
 */
public class FulfillmentInputStream extends OerInputStream {

    public FulfillmentInputStream(InputStream stream) {
        super(stream);
    }

    /**
     * Read a fulfillment from the underlying stream using OER encoding per the
     * specification:
     *
     * Fulfillment ::= SEQUENCE { type ConditionType, payload OCTET STRING }
     *
     * ConditionType ::= INTEGER { preimageSha256(0), rsaSha256(1),
     * prefixSha256(2), thresholdSha256(3), ed25519(4) } (0..65535)
     *
     * @return
     * @throws IOException
     * @throws OerDecodingException
     * @throws UnsupportedConditionException
     */
    public Fulfillment readFulfillment()
            throws IOException, UnsupportedConditionException, OerDecodingException {
        final ConditionType type = readConditiontype();
        final FulfillmentPayload payload = new FulfillmentPayload(this.readPayload());

        ByteArrayInputStream byteStream = new ByteArrayInputStream(payload.payload);
        FulfillmentInputStream stream01 = new FulfillmentInputStream(byteStream);

        try {
            switch (type) {
                case PREIMAGE_SHA256:
                    return new PreimageSha256Fulfillment(ConditionType.PREIMAGE_SHA256, payload);
                case PREFIX_SHA256:
                    byte[] prefix = stream01.readOctetString();
                    Fulfillment subfulfillment = stream01.readFulfillment();
                    return new PrefixSha256Fulfillment(ConditionType.PREFIX_SHA256, payload, prefix, subfulfillment);
                case RSA_SHA256:
                    /*
                     * REF: https://interledger.org/five-bells-condition/spec.html#rfc.section.4.4.2
                     * RsaSha256FulfillmentPayload ::= SEQUENCE {
                     * modulus OCTET STRING (SIZE(128..512)),
                     * signature OCTET STRING (SIZE(128..512))
                     * }
                     */
                    byte[] bytesModulus = stream01.readOctetString();
                    byte[] bytesSignatureRSASHA256 = stream01.readOctetString();
                    BigInteger modulus = new BigInteger(1, bytesModulus); // TODO: RECHECK
System.out.println(modulus);
System.out.println(new BigInteger(bytesSignatureRSASHA256));
                    SignaturePayload signature01 = new SignaturePayload(bytesSignatureRSASHA256);
                    return new RsaSha256Fulfillment(ConditionType.RSA_SHA256, payload, modulus, signature01);
                case ED25519:
                    /*
                 * REF: https://interledger.org/five-bells-condition/spec.html#rfc.section.4.5.2
                 * Ed25519FulfillmentPayload ::= SEQUENCE {
                 *     publicKey OCTET STRING (SIZE(32)),
                 *     signature OCTET STRING (SIZE(64))
                 * }
                     */
                    byte[] bytesPublicKey = stream01.readOctetString();
                    byte[] bytesSignatureEd25519 = stream01.readOctetString();
                    java.security.PublicKey publicKey = Ed25519Fulfillment.publicKeyFromByteArray(new KeyPayload(bytesPublicKey));
                    SignaturePayload signature02 = new SignaturePayload(bytesSignatureEd25519);
                    return new Ed25519Fulfillment(ConditionType.ED25519, payload, publicKey, signature02);
                case THRESHOLD_SHA256:
                    int threshold = stream01.readVarUInt();
                    int conditionCount = stream01.readVarUInt();
                    
                    java.util.List<Integer>     weight_l = new java.util.ArrayList<Integer>();
                    java.util.List<Fulfillment> ff_l     = new java.util.ArrayList<Fulfillment>();
                    for (int idx=0; idx < conditionCount; idx++) {
                        int weight = stream01.readVarUInt();
                        weight_l.add(weight);
                        Fulfillment ff = stream01.readFulfillment();
                        ff_l.add(ff);
                    }
                    return new ThresholdSHA256Fulfillment(ConditionType.THRESHOLD_SHA256, payload, threshold, weight_l, ff_l);
                default:
                    throw new RuntimeException("Unimplemented fulfillment type encountered.");
            }
        } catch (Exception e) {
            throw new RuntimeException(e.toString(), e);
        } finally {
            stream01.close();
        }

    }

    protected ConditionType readConditiontype()
            throws IOException {
        int value = read16BitUInt();
        return ConditionType.valueOf(value);
    }

    protected byte[] readPayload()
            throws IOException, UnsupportedLengthException, IllegalLengthIndicatorException {

        return readOctetString();
    }

}

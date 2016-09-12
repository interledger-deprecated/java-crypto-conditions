package org.interledger.cryptoconditions;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.regex.Pattern;

import org.interledger.cryptoconditions.encoding.Base64Url;
import org.interledger.cryptoconditions.encoding.FulfillmentInputStream;
import org.interledger.cryptoconditions.encoding.FulfillmentOutputStream;

public class FulfillmentFactory {

    private static final String FULFILLMENT_FORMAT = "^cf:([1-9a-f][0-9a-f]{0,3}|0):[a-zA-Z0-9_-]*$";
    private static final Pattern fulfillmentFormat = Pattern.compile(FULFILLMENT_FORMAT);

    public static Fulfillment getFulfillmentFromURI(String uri) {
        if (uri == null) {
            throw new IllegalArgumentException("serializedFulfillment == null");
        }
        if ("".equals(uri.trim())) {
            throw new IllegalArgumentException("serializedFulfillment was an empy string");
        }
        if (!uri.startsWith("cf:")) {
            throw new IllegalArgumentException("serializedFulfillment must start with 'cf:'");
        }

        java.util.regex.Matcher m = fulfillmentFormat.matcher(uri);
        if (!m.matches()) {
            throw new IllegalArgumentException(
                    "serializedFulfillment '" + uri + "' doesn't match " + FulfillmentFactory.FULFILLMENT_FORMAT);
        }
        String[] pieces = uri.split(":");

        String BASE16Type = pieces[1];
        String BASE64URLPayload = (pieces.length == 3) ? pieces[2] : "" /*case empty payload*/;

        ConditionType type = ConditionType.valueOf(Integer.parseInt(BASE16Type, 16));

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        FulfillmentOutputStream ffos = new FulfillmentOutputStream(baos);
        try {
            ffos.writeConditionType(type);
            ffos.writeOctetString(Base64Url.decode(BASE64URLPayload));

            byte[] input_stream = baos.toByteArray();
            ByteArrayInputStream bais = new ByteArrayInputStream(input_stream);
            FulfillmentInputStream ffis = new FulfillmentInputStream(bais);

            Fulfillment result = ffis.readFulfillment();
            try {
                ffis.close(); // TODO: FIXME Drop throw IOException
            } catch (Exception e) {/*no exceptions for in-memory bytearrays*/ }
            return result;
        } catch (Exception e) {
            // This must never happen. The stream sources are in-memory byte arrays.
            throw new RuntimeException(e.toString(), e);
        } finally {
            ffos.close();
        }
    }

    /*
     * 
     */
}

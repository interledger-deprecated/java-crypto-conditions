package org.interledger.cryptoconditions;

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;

import org.junit.Test;

import net.i2p.crypto.eddsa.Utils;

import org.interledger.cryptoconditions.Fulfillment;
import org.interledger.cryptoconditions.encoding.FulfillmentOutputStream;
import org.interledger.cryptoconditions.encoding.FulfillmentInputStream;
import org.interledger.cryptoconditions.encoding.OerDecodingException;
import org.interledger.cryptoconditions.types.*;

// TODO:(0) Complete tests

public class TestEd25519Fulfillment {

    static {
        Ed25519Fulfillment.UserHasReadEd25519JavaDisclaimerAndIsAwareOfSecurityIssues();
    }

    final byte[] TEST_SEED = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000");
    static final byte[] TEST_PK = Utils.hexToBytes("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29");
    static final byte[] TEST_MSG = "This is a secret message".getBytes(Charset.forName("UTF-8"));
    static final byte[] TEST_FF_PAYLOAD = Utils.hexToBytes(
         "0004603b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da2994825896c7075c31bcb81f06dba2bdcd9dcf16e79288d4b9f87c248215c8468d475f429f3de3b4a2cf67fe17077ae19686020364d6d4fa7a0174bab4a123ba0f");
    static final byte[] TEST_KO_MSG = "This is a wrong secret message".getBytes(Charset.forName("UTF-8"));
    static final byte[] TEST_MSG_SIG = Utils.hexToBytes(
        "94825896c7075c31bcb81f06dba2bdcd9dcf16e79288d4b9f87c248215c8468d475f429f3de3b4a2cf67fe17077ae19686020364d6d4fa7a0174bab4a123ba0f");
    static final byte[] TEST_KO_MSG_SIG = Utils.hexToBytes(
        "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111");

    private Fulfillment getPayload(byte[] ffOEREncoded) throws IOException, UnsupportedConditionException, OerDecodingException{
        ByteArrayInputStream auxi = new ByteArrayInputStream(ffOEREncoded);
        FulfillmentInputStream ffOut = new FulfillmentInputStream(auxi);
        Fulfillment  result = ffOut.readFulfillment();
        
        ffOut.close();
        return result;
    }

    @Test
    public void testEd25519Fulfillment() throws IOException, UnsupportedConditionException, OerDecodingException {
        Fulfillment ff;
        System.out.println("testEd25519Fulfillment start:");
//        ff = getPayload(TEST_FF_PAYLOAD);
//        ff.getCondition();
//
//        assertTrue("Fulfillment validates TEST_MSG", ff.validate(new MessagePayload(TEST_MSG)));

//        byteStream = new ByteArrayInputStream( getPayload(TEST_PK, TEST_MSG_SIG) );
//        stream = new FulfillmentInputStream(byteStream);
//        Fulfillment ffKO = stream.readFulfillment();
//        stream.close();
//        ff.getCondition();
//        assertFalse("Fulfillment validates TEST_MSG", ffKO.validate(new MessagePayload(TEST_MSG)));
        

        // Build from secret
        ff = Ed25519Fulfillment.BuildFromSecrets(new KeyPayload(TEST_SEED), new MessagePayload(TEST_MSG));
        ff.getCondition();
        assertTrue("Fulfillment validates TEST_MSG", ff.validate(new MessagePayload(TEST_MSG)));
        
        ff = Ed25519Fulfillment.BuildFromSecrets(new KeyPayload(TEST_SEED), new MessagePayload(TEST_KO_MSG));
        ff.getCondition();
        assertFalse("Fulfillment validates TEST_MSG", ff.validate(new MessagePayload(TEST_MSG)));
        

       
        
    }

}

package org.interledger.cryptoconditions;

import static org.junit.Assert.*;

import javax.xml.bind.DatatypeConverter;

import org.junit.Test;

// TODO:(0) Complete tests
public class TestPreimageSha256Fulfillment {

    @Test
    public void testCreatePreimageSha256FulfillmentFromPreimage() {
        System.out.println("testCreatePreimageSha256FulfillmentFromPreimage");
        // TODO:(?) Create unified test data for all different implementations (JS, java, Python, ...)
        String[][] testData01 = { // Copy & Paste from five-bells-condition test data
            /* preimg , fulfillment, condition */
            {"", "cf:0:", "cc:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0"},
            {"00", "cf:0:AA", "cc:0:3:bjQLnP-zepicpUTmu3gKLHiQHT-zNzh2hRGjBhevoB0:1"},
            {"ff", "cf:0:_w", "cc:0:3:qBAK5qoZQNC2Y7sxzUZhQuu9vVGHExuS2TgYmHgy64k:1"},
            {"feff", "cf:0:_v8", "cc:0:3:8ZdpKBDUV-KX_OnFZTsCWB_5mlCFI3DynX5f5H2dN-Y:2"},
            {"fffe", "cf:0:__4", "cc:0:3:s9UQ7wQnXKjmmOWzy7Ds45Se-SUvDNyDnp7jR0CaIgk:2"},
            {"00ff", "cf:0:AP8", "cc:0:3:But9amnuGeX733SQGNPSq_oEvL0TZdsxLrhtxxaTibg:2"},
            {"0001", "cf:0:AAE", "cc:0:3:tBP0fRPuL-bIRbLuFBr4HehY307FSaWLeXC7lmRbyNI:2"},
            {"616263", "cf:0:YWJj", "cc:0:3:ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0:3"},};

        for (int idx = 0; idx < testData01.length; idx++) {
            String[] testDataRow01 = testData01[idx];
            String base16preimage = testDataRow01[0];
            byte[] preimage = DatatypeConverter.parseHexBinary(base16preimage);
            String expectedFfURI = testDataRow01[1], expectedCCURI = testDataRow01[2];
            Fulfillment ff = PreimageSha256Fulfillment.BuildFromSecrets(preimage);
//            System.out.println("                    ffURI:"+ffURI);
//            System.out.println("ff.toURI()               :"+ff.toURI());;
            assertTrue("ffURI.equals(ff.toURI())", expectedFfURI.equals(ff.toURI()));
//            System.out.println("      expectedCCURI:"+expectedCCURI);
//            System.out.println("Condition().toURI():"+ff.getCondition().toURI());
            assertTrue(expectedCCURI.equals(ff.getCondition().toURI()));
        }
    }
}

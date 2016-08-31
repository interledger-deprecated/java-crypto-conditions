package org.interledger.cryptoconditions;


import static org.junit.Assert.*;

import org.junit.Test;


import org.interledger.cryptoconditions.Fulfillment;

// TODO:(0) Complete tests
public class TestPrefixSha256Fulfillment {

    @Test
    public void testCreate() {
    	String preimage = "616263";
        Fulfillment PreimageSubff = PreimageSha256Fulfillment.BuildFromSecrets(preimage.getBytes());
        byte[] prefix = {1,2,3,4};
        Fulfillment ffPrefix = PrefixSha256Fulfillment.BuildFromParams(prefix, PreimageSubff);
        String ffPrefixURI = ffPrefix.getCondition().toURI();
        assertTrue("ffPrefixURI equals TODO:(0)", ffPrefixURI.length()>0);
    }
}

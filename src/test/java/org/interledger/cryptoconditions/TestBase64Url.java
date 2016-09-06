package org.interledger.cryptoconditions;

import static org.junit.Assert.*;

import org.junit.Test;

import org.interledger.cryptoconditions.encoding.Base64Url;

public class TestBase64Url {

    @Test
    public void testDecode() {
        String[] td = TestData.Base64URLEncoded;
        for (short idx=0; idx < td.length ; idx++){
            String input = td[idx], output = Base64Url.encode( Base64Url.decode(input) );
            assertTrue("'"+input+"' equals '"+output +"' ", input.equals(output) );
        }
    }

    @Test
    public void testEncode() {
        byte[] input = {0,1,2,3,4,5,6,7,8,9};
        byte[] output = Base64Url.decode( Base64Url.encode(input) );
        assertTrue ("input array == output array", java.util.Arrays.equals(input, output));
    }

}

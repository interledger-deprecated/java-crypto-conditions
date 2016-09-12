package org.interledger.cryptoconditions;

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import org.interledger.cryptoconditions.encoding.ConditionInputStream;
import org.interledger.cryptoconditions.encoding.OerDecodingException;
import org.junit.Test;

public class TestDecodeCondition {

    @Test
    public final void testReadPreimageSha256Condition0x00() throws IOException, UnsupportedConditionException, OerDecodingException {

        ByteArrayInputStream b = new ByteArrayInputStream(TestData.PreimageSha256Condition0x00);
        ConditionInputStream in = new ConditionInputStream(b);

        Condition c = in.readCondition();

        in.close();

        assertEquals(c.getType(), ConditionType.PREIMAGE_SHA256);
        assert (c.getFeatures().contains(FeatureSuite.SHA_256));
        assert (c.getFeatures().contains(FeatureSuite.PREIMAGE));
        assertArrayEquals(c.getFingerprint(), new byte[]{0x00});
        assertEquals(c.getMaxFulfillmentLength(), 1);

    }

}

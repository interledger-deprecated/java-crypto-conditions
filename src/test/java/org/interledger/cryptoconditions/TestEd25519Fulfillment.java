package org.interledger.cryptoconditions;

import static org.junit.Assert.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;

import org.junit.Test;

import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.Utils;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;

import org.interledger.cryptoconditions.Fulfillment;
import org.interledger.cryptoconditions.types.*;

// TODO:(0) Complete tests

public class TestEd25519Fulfillment {

    private static EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName("ed25519-sha-512");

	static {
	    final byte[] TEST_SEED = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000");
        try {
            Signature sgr = new EdDSAEngine(MessageDigest.getInstance("SHA-512"));
            EdDSAPrivateKeySpec privKey = new EdDSAPrivateKeySpec(TEST_SEED, spec);
            PrivateKey sKey = new EdDSAPrivateKey(privKey);
            sgr.initSign(sKey);

        }catch(Exception e){
            throw new RuntimeException(e.toString(), e);
        }
	}
    static final byte[] TEST_PK = Utils.hexToBytes("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29");
    static final byte[] TEST_MSG = "This is a secret message".getBytes(Charset.forName("UTF-8"));
    static final byte[] TEST_MSG_SIG = Utils.hexToBytes(
    		"94825896c7075c31bcb81f06dba2bdcd9dcf16e79288d4b9f87c248215c8468d475f429f3de3b4a2cf67fe17077ae19686020364d6d4fa7a0174bab4a123ba0f");


	@Test
	public void testEncode() {
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		try {
			buffer.write(TEST_PK);
			buffer.write(TEST_MSG_SIG);
		} catch (IOException e) {
			throw new RuntimeException(e);
		} 
		FulfillmentPayload payload = new FulfillmentPayload(buffer.toByteArray());
		Ed25519Fulfillment.UserHasReadEd25519JavaDisclaimerAndIsAwareOfSecurityIssues();
		Fulfillment ff = new Ed25519Fulfillment(ConditionType.ED25519, payload);
		ff.getCondition();
		assertTrue("Fulfillment validates TEST_MSG", ff.validate(new MessagePayload(TEST_MSG)));
		
	}

}

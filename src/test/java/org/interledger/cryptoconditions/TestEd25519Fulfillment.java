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
		Ed25519Fulfillment.UserHasReadEd25519JavaDisclaimerAndIsAwareOfSecurityIssues();
	}

    final byte[] TEST_SEED = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000");
    static final byte[] TEST_PK = Utils.hexToBytes("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29");
    static final byte[] TEST_MSG = "This is a secret message".getBytes(Charset.forName("UTF-8"));
    static final byte[] TEST_KO_MSG = "This is a wrong secret message".getBytes(Charset.forName("UTF-8"));
    static final byte[] TEST_MSG_SIG = Utils.hexToBytes(
    	"94825896c7075c31bcb81f06dba2bdcd9dcf16e79288d4b9f87c248215c8468d475f429f3de3b4a2cf67fe17077ae19686020364d6d4fa7a0174bab4a123ba0f");
    static final byte[] TEST_KO_MSG_SIG = Utils.hexToBytes(
    	"11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111");

    
    private FulfillmentPayload getPayload(byte[] publicKey, byte[] msg_sig){
		//Ed25519FulfillmentPayload ::= SEQUENCE {
		//    publicKey OCTET STRING (SIZE(32)),
		//    signature OCTET STRING (SIZE(64))
		//}
    	ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		try {
			buffer.write(publicKey);
			buffer.write(msg_sig);
		} catch (IOException e) {
			throw new RuntimeException(e);
		} 
		return new FulfillmentPayload(buffer.toByteArray());
    }

	@Test
	public void testEd25519Fulfillment() {
		System.out.println("testEd25519Fulfillment start:");

		// Build from payload (public pubKey + public MsgSignature)
		Fulfillment ff = new Ed25519Fulfillment(ConditionType.ED25519, getPayload(TEST_PK, TEST_MSG_SIG));
		ff.getCondition();
		assertTrue("Fulfillment validates TEST_MSG", ff.validate(new MessagePayload(TEST_MSG)));

		Fulfillment ffKO = new Ed25519Fulfillment(ConditionType.ED25519, getPayload(TEST_PK, TEST_KO_MSG_SIG));
		ff.getCondition();
		assertFalse("Fulfillment validates TEST_MSG", ffKO.validate(new MessagePayload(TEST_MSG)));
		

		// Build from secret
		ff = Ed25519Fulfillment.BuildFromSecrets(new KeyPayload(TEST_SEED), new MessagePayload(TEST_MSG));
		ff.getCondition();
		assertTrue("Fulfillment validates TEST_MSG", ff.validate(new MessagePayload(TEST_MSG)));
		
		ff = Ed25519Fulfillment.BuildFromSecrets(new KeyPayload(TEST_SEED), new MessagePayload(TEST_KO_MSG));
		ff.getCondition();
		assertFalse("Fulfillment validates TEST_MSG", ff.validate(new MessagePayload(TEST_MSG)));
		
	}

}

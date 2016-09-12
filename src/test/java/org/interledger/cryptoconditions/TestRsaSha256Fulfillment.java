package org.interledger.cryptoconditions;


import java.math.BigInteger;
import java.security.SecureRandom;

import static org.junit.Assert.*;

//import javax.xml.bind.DatatypeConverter;

//import org.interledger.cryptoconditions.types.KeyPayload;
import org.interledger.cryptoconditions.types.MessagePayload;
import org.junit.Test;

import net.i2p.crypto.eddsa.Utils;

//import org.interledger.cryptoconditions.types.MessagePayload;

// TODO:(0) Complete tests
public class TestRsaSha256Fulfillment {

    @Test
    public void testCreateRsaShaFullfillmentFromSecrets() {
        String privateKey  = "-----BEGIN RSA PRIVATE KEY-----\n"
            + "MIIEpAIBAAKCAQEA4e+LJNb3awnIHtd1KqJi8ETwSodNQ4CdMc6mEvmbDJeotDdB\n" + "U+Pu89ZmFoQ+DkHCkyZLcbYXPbHPDWzVWMWGV3Bvzwl/cExIPlnL/f1bPue8gNdA\n"
            + "xeDwR/PoX8DXWBV3am8/I8XcXnlxOaaILjgzakpfs2E3Yg/zZj264yhHKAGGL3Ly\n" + "+HsgK5yJrdfNWwoHb3xT41A59n7RfsgV5bQwXMYxlwaNXm5Xm6beX04+V99eTgcv\n"
            + "8s5MZutFIzlzh1J1ljnwJXv1fb1cRD+1FYzOCj02rce6AfM6C7bbsr+YnWBxEvI0\n" + "TZk+d+VjwdNh3t9X2pbvLPxoXwArY4JGpbMJuQIDAQABAoIBAAF1UVmYhZpMQt1o\n"
            + "GJqA19CjMUXZ37bK0rjqk4nV0JlhNTaMkMBg3T73qEsG6XugEwhuG9iNC1NbnXGB\n" + "vVLIW5ie4inc7tSjuWelnrpx8y/RwRa3zPQ6AnMEcQCFNx6bbNzkAO1TLpvxfriX\n"
            + "iZN6y2IpPrriqr/YSILlbRpgPS1V6hLre0wewFyyX6/REtutApRiEe2oiklYvznz\n" + "8Zf4wCvtrv6K1+r0Eeq6VgjcgGgi1xWOI8TXyCwWGAOQ9TKVOSw6/jpo6pELRWYS\n"
            + "pVwsR8U/0L4ZeyYm/w5AGwmQKrlI/uL9vauGKRg55Bj7DjzXOgcRuTuTFZSM/+w/\n" + "z1XpdPECgYEA/ZJGAD61SplbvSsfmI3KxupBnT5c0vxdVpLpc6JXpeHJmnJZvIpN\n"
            + "dssuTjJlD+LgTb03DSGmVWTpyvAS6L7Xx0OgB0YQbiQHjcLJpbrREv9XAohH1+Al\n" + "W11Cx7ukKpA9tmPM76BBKInhZqfrG0ihfbBBG5i5PNdd97WstjQOdRUCgYEA5BmC\n"
            + "wVcYdHfIvKj+AE0GNWOM1RGaeJisVF7BQOCBXxmjEUHSqjf+ddDsTODvrSnNTg6P\n" + "Lu56Q1fIhx1hY7kYLlnDZBcC192+AvM2QHw8rDJ851ZiruluujhXdZpjRnCO9Mqa\n"
            + "4d53yXC/Z7G4VSyn15DDylIahyLRueILErr/cxUCgYBVPqdpzasEuSmuHqEwl/pj\n" + "hL0qL5zlERIP2LPCvADbM1yjH24rhBMmrIeUojx3ar4dZE7tizJv4sz1/F9e/0lr\n"
            + "I8DYsSU04cfoUGOZ44QF7vFBWK9OU3w7is64dsxpwrP8bPCoXieJiVDNQgY31eL0\n" + "bhx1OpKLcZuVeu3lEvsJQQKBgQCAHqAmDtCqopl69oTtEFZ7aHYzO5cDQ+YP4cU0\n"
            + "tqWUECdayxkUCS2BaZ9As1uMbR1nSaA9ITBFYSo+Uk9gnxeo+TxZnN849tECgS+o\n" + "2t+NbTJhElGNo4pRSNI/OT+n0hNKBf8m/TlVSWIJUXaTSOjhmOuQWbuSygj5GrFT\n"
            + "jPts3QKBgQCnjsKTyZmtRPz0PeJniSsp22njYM7EuE69OtItGxq/N7SA/zxowo3z\n" + "zcAXbOIsnmoLCKGoIB9Cw7wO5OWSkB3fkaT6zUHzxpxBGtlROWtLAsflX0amCp4f\n"
            + "7CKh5blJ1yGJtNc+Q5qyUbyntoIzFGCibva+xz3UqhJt5Q4TlCy+5Q==\n"
            + "-----END RSA PRIVATE KEY-----\n";
        byte[] message = "aaa".getBytes();
        byte[] salt = new byte[32];  // Java specs warranties it is initialized to zeros.
        byte[] modulus = Utils.hexToBytes(
            "e1ef8b24d6f76b09c81ed7752aa262f044f04a874d43809d31cea612f99b0c97a8b4374153e3eef3d66616843e0e41c293264b71b6173db1cf0d6cd558c58657706fcf097f704c483e59cbfdfd5b3ee7bc80d740c5e0f047f3e85fc0d75815776a6f3f23c5dc5e797139a6882e38336a4a5fb36137620ff3663dbae328472801862f72f2f87b202b9c89add7cd5b0a076f7c53e35039f67ed17ec815e5b4305cc63197068d5e6e579ba6de5f4e3e57df5e4e072ff2ce4c66eb452339738752759639f0257bf57dbd5c443fb5158cce0a3d36adc7ba01f33a0bb6dbb2bf989d607112f2344d993e77e563c1d361dedf57da96ef2cfc685f002b638246a5b309b9");
        // Note: With PSS padding the generated signature will be different each new run, not deterministic. Next one is just a "random" one
        //     for a given random PSS padding
//        String signature = 
//            "48e8945efe007556d5bf4d5f249e4808f7307e29511d3262daef61d88098f9aa4a8bc0623a8c975738f65d6bf459d543f289d73cbc7af4ea3a33fbf3ec4440447911d72294091e561833628e49a772ed608de6c44595a91e3e17d6cf5ec3b2528d63d2add6463989b12eec577df6470960df6832a9d84c360d1c217ad64c8625bdb594fb0ada086cdecbbde580d424bf9746d2f0c312826dbbb00ad68b52c4cb7d47156ba35e3a981c973863792cc80d04a180210a52415865b64b3a61774b1d3975d78a98b0821ee55ca0f86305d42529e10eb015cefd402fb59b2abb8deee52a6f2447d2284603d219cd4e8cf9cffdd5498889c3780b59dd6a57ef7d732620";
        String FF_KO = "cf:3:ggEA4e-LJNb3awnIHtd1KqJi8ETwSodNQ4CdMc6mEvmbDJeotDdBU-Pu89ZmFoQ-DkHCkyZLcbYXPbHPDWzVWMWGV3Bvzwl_cExIPlnL_f1bPue8gNdAxeDwR_PoX8DXWBV3am8_I8XcXnlxOaaILjgzakpfs2E3Yg_zZj264yhHKAGGL3Ly-HsgK5yJrdfNWwoHb3xT41A59n7RfsgV5bQwXMYxlwaNXm5Xm6beX04-V99eTgcv8s5MZutFIzlzh1J1ljnwJXv1fb1cRD-1FYzOCj02rce6AfM6C7bbsr-YnWBxEvI0TZk-d-VjwdNh3t9X2pbvLPxoXwArY4JGpbMJuYIBAEjolF7-AHVW1b9NXySeSAj3MH4pUR0yYtrvYdiAmPmqSovAYjqMl1c49l1r9FnVQ_KJ1zy8evTqOjP78-xEQER5EdcilAkeVhgzYo5Jp3LtYI3mxEWVqR4-F9bPXsOyUo1j0q3WRjmJsS7sV332Rwlg32gyqdhMNg0cIXrWTIYlvbWU-wraCGzey73lgNQkv5dG0vDDEoJtu7AK1otSxMt9RxVro146mByXOGN5LMgNBKGAIQpSQVhltks6YXdLHTl114qYsIIe5Vyg-GMF1CUp4Q6wFc79QC-1myq7je7lKm8kR9IoRgPSGc1OjPnP_dVJiInDeAtZ3WpX731zJiA";
//        String CC_OK = "cc:3:11:uKkFs6dhGZCwD51c69vVvHYSp25cRi9IlvXfFaxhMjo:518";
        
        SecureRandom saltRandom = new SecureRandom(salt);
        // Build from secrets.
        RsaSha256Fulfillment ffFromSecrets = RsaSha256Fulfillment.BuildFromSecrets(privateKey, message, saltRandom);
        BigInteger expectedModulus = new BigInteger(1, modulus);
        assertTrue(ffFromSecrets.getModulus().compareTo(expectedModulus) == 0);
        assertTrue(ffFromSecrets.validate(new MessagePayload(message)));

        Fulfillment ffFromURI = FulfillmentFactory.getFulfillmentFromURI(FF_KO);
        ffFromURI.validate(new MessagePayload(message));


    }
}









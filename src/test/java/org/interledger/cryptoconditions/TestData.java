package org.interledger.cryptoconditions;

public class TestData {

    public static final byte[] PreimageSha256Condition0x00 = new byte[]{
        0x00, 0x00, //Type = PREIMAGE SHA256
        0x01, 0x03, //Features = SHA256 and PREIMAGE
        0x01, 0x00, //Fingerprint = 0x00
        0x01, 0x01, //Max fulfillment = 1
    };

    public static final byte[] PreimageSha256Condition0xFF = new byte[]{
        0x00, 0x00, //Type = PREIMAGE SHA256
        0x01, 0x03, //Features = SHA256 and PREIMAGE
        0x01, (byte) 0xFF, //Fingerprint = 0x00
        0x01, 0x01, //Max fulfillment = 1
    };

    public static final String[] Base64URLEncoded = new String[]{ /* "random" Base64URL encoded strings extracted from five-bells-conditions Tests */
        "ff00ff00abab",
        "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik",
        "RCmTBlAEqh5MSPTdAVgZTAI0m8xmTNluQA6iaZGKjVE",
        "Yja3qFj7NS_VwwE7aJjPJos-uFCzStJlJLD4VsNy2XM",
        "XkflBmyISKuevH8-850LuMrzN-HT1Ds9zKUEzaZ2Wk0",
        "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2imPiVs8r-LJUGA50OKmY4JWgARnT-jSN3hQkuQNaq9IPk_GAWhwXzHxAVlhOM4hqjV8DTKgZPQj3D7kqjq_U_gD",
        "RCmTBlAEqh5MSPTdAVgZTAI0m8xmTNluQA6iaZGKjVGfTbzglso5Uo3i2O2WVP6abH1dz5k0H5DLylizTeL5UC0VSptUN4VCkhtbwx3B00pCeWNy1H78rq6OTXzok-EH",
        "IHahWSBEpuT1ESZbynOmBNkLBSnR32Ar4woZqSV2YNH1QK7Gq2qRIq_w99y5Zn_2ExNolHMrbnjCb1tnMQHiZ_4uK2X6TVPa1HihraZNUP0d_bfZSSDcPhpWSmR7HLo1YAE",
        "Bv8A_wCrqwAEYCB2oVkgRKbk9REmW8pzpgTZCwUp0d9gK-MKGakldmDR9UCuxqtqkSKv8PfcuWZ_9hMTaJRzK254wm9bZzEB4mf-Litl-k1T2tR4oa2mTVD9Hf232Ukg3D4aVkpkexy6NQ",};
}

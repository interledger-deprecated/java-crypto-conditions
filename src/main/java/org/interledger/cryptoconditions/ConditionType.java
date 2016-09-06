package org.interledger.cryptoconditions;

/**
 * Enumeration of crypto-condition types
 *
 * @author adrianhopebailie
 *
 */
public enum ConditionType {

    PREIMAGE_SHA256(0),
    PREFIX_SHA256(1),
    THRESHOLD_SHA256(2),
    RSA_SHA256(3),
    ED25519(4);

    private final int typeCode;

    ConditionType(int typeCode) {
        this.typeCode = typeCode;
    }

    /**
     * Get the ASN.1 enum code for this type
     *
     * @return the ASN.1 enumeration
     */
    public int getTypeCode() {
        return this.typeCode;
    }

    public static ConditionType valueOf(int typeCode) {
        switch (typeCode) {
            case 0:
                return ConditionType.PREIMAGE_SHA256;
            case 1:
                return ConditionType.PREFIX_SHA256;
            case 2:
                return ConditionType.THRESHOLD_SHA256;
            case 3:
                return ConditionType.RSA_SHA256;
            case 4:
                return ConditionType.ED25519;

            default:
                throw new IllegalArgumentException("Invalid Condition Type code " + typeCode);
        }
    }

}

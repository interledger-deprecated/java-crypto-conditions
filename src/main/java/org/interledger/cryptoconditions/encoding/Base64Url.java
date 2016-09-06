package org.interledger.cryptoconditions.encoding;

public class Base64Url {

    private static final String CODES = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=";
    private static final int[] LOOKUP = new int[123]; // (int) 'z' == 122 and is the max

    static {
        char[] code_chars = CODES.toCharArray();
        for (int i = 0; i < 122; i++) {
            LOOKUP[i] = -1;
        }
        for (int i = 0; i < 65; i++) {
            LOOKUP[(int) code_chars[i]] = i;
        }
    }

    public static byte[] decode(String input) {
        int padLength = (input.length() % 4 == 0) ? 0 : 4 - (input.length() % 4);
        for (int pad = 0; pad < padLength; pad++) {
            input += "=";
        }
        if (input.length() % 4 != 0) {
            throw new IllegalArgumentException("Invalid base64url input");
        }

        byte decoded[] = new byte[((input.length() * 3) / 4) - (input.indexOf('=') > 0 ? (input.length() - input.indexOf('=')) : 0)];
        char[] inChars = input.toCharArray();
        int j = 0;
        int b[] = new int[4];
        for (int i = 0; i < inChars.length; i += 4) {
            b[0] = LOOKUP[(int) inChars[i]];
            b[1] = LOOKUP[(int) inChars[i + 1]];
            b[2] = LOOKUP[(int) inChars[i + 2]];
            b[3] = LOOKUP[(int) inChars[i + 3]];

            if (b[0] == -1 || b[1] == -1 || b[2] == -1 || b[3] == -1) //TODO Return position of bad character
            {
                throw new IllegalArgumentException("Invalid base64url input, illegal character.");
            }

            decoded[j++] = (byte) ((b[0] << 2) | (b[1] >> 4));
            if (b[2] < 64) {
                decoded[j++] = (byte) ((b[1] << 4) | (b[2] >> 2));
                if (b[3] < 64) {
                    decoded[j++] = (byte) ((b[2] << 6) | b[3]);
                }
            }
        }

        return decoded;
    }

    public static String encode(byte[] in) {
        StringBuilder out = new StringBuilder((in.length * 4) / 3);
        int b;
        for (int i = 0; i < in.length; i += 3) {
            b = (in[i] & 0xFC) >> 2;
            out.append(CODES.charAt(b));
            b = (in[i] & 0x03) << 4;
            if (i + 1 < in.length) {
                b |= (in[i + 1] & 0xF0) >> 4;
                out.append(CODES.charAt(b));
                b = (in[i + 1] & 0x0F) << 2;
                if (i + 2 < in.length) {
                    b |= (in[i + 2] & 0xC0) >> 6;
                    out.append(CODES.charAt(b));
                    b = in[i + 2] & 0x3F;
                    out.append(CODES.charAt(b));
                } else {
                    out.append(CODES.charAt(b));
                    // out.append('=');
                }
            } else {
                out.append(CODES.charAt(b));
                // out.append("==");
            }
        }

        return out.toString();
    }
}

package com.laowang.algorithm;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class SafeBase64 {
    private static final char[] legalChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            .toCharArray();

    private static int byte2Int(byte b) {
        if (b < 0) {
            return 256 + b;
        } else {
            return b;
        }
    }

    /**
     * base64编码
     * @param data
     * @return
     */
    public static String encode(byte[] data) {
        int[] c = new int[3];
        int[] w = new int[4];
        int n, i;
        String retry = "";
        int tl;
        tl = data.length - 1;
        for (n = 0; n <= tl; n = n + 3) {
            c[0] = byte2Int(data[n]);
            for (i = 1; i < 3; i++) {
                if (n + i > tl) {
                    c[i] = 0;
                } else {
                    c[i] = byte2Int(data[n + i]);
                }
            }
            //// System.out.println("c[0]=" + c[0]);
            w[0] = (int) (c[0] / 4);
            w[1] = (int) ((c[0] & 3) * 16 + (int) (c[1] / 16));

            if (tl >= n + 1) {
                w[2] = (int) ((c[1] & 15) * 4 + (int) (c[2] / 64));
            } else {
                w[2] = -1;
            }
            if (tl >= n + 2) {
                w[3] = (int) (c[2] & 63);
            } else {
                w[3] = -1;
            }
            for (i = 0; i < 4; i++) {
                if (w[i] >= 0) {
                    retry += mimeencode(w[i]);
                }
            }
            //// System.out.println("retry=" + retry);
        }
        return retry;
    }

    private static char mimeencode(int w) {
        return legalChars[w];
    }

    private static int mimedecode(char a) {
        int j;
        for (j = 0; j < legalChars.length; j++) {
            if (a == legalChars[j]) {
                break;
            }
        }
        if (j >= legalChars.length) {
            return -1;
        } else {
            return j;
        }
    }

    public static byte[] decode(String s) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try {
            decode(s, bos);
        } catch (IOException e) {
            throw new RuntimeException();
        }
        byte[] decodedBytes = bos.toByteArray();
        try {
            bos.close();
            bos = null;
        } catch (IOException ex) {
            ex.printStackTrace();
        }
        return decodedBytes;
    }

    private static void decode(String s, OutputStream os) throws IOException {
        byte[] w = new byte[4];
        int n, i;
        int tl;
        tl = s.length() - 1;
        for (n = 0; n <= tl; n = n + 4) {
            for (i = 0; i < 4; i++) {
                if (n + i > tl) {
                    w[i] = -1;
                } else {
                    w[i] = (byte) mimedecode(s.charAt(n + i));
                }
            }
            if (w[1] >= 0) {
                os.write((byte) ((w[0] * 4 + (byte) (w[1] / 16)) & 255));
            }
            if (w[2] >= 0) {
                os.write((byte) ((w[1] * 16 + (byte) (w[2] / 4)) & 255));
            }
            if (w[3] >= 0) {
                os.write((byte) ((w[2] * 64 + w[3]) & 255));
            }
        }
    }

    /**
     * 检测输入的字符串是否是符合base64编码后的格式
     *
     * @param str
     * @return true/false
     */
    public static boolean checkBase64Char(String str) {
        boolean isBase64Char = true;
        int i, j;
        if (str == null) {
            return false;
        }
        for (i = 0; i < str.length(); i++) {
            for (j = 0; j < legalChars.length; j++) {
                if (str.charAt(i) == legalChars[j]) {
                    break;
                }
            }
            if (j >= legalChars.length) {
                break;
            }
        }
        if (i < str.length()) {
            isBase64Char = false;
        }
        return isBase64Char;
    }

}
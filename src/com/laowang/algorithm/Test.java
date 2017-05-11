package com.laowang.algorithm;


import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.MessageDigest;

public class Test {

    public static void main(String[] args) {

        String objectStr = "58d7cf41e1e8fc0543a00dbe";
        String md5 = createMD5(objectStr);
        int type = 1;
        long id1 = 1001;
        long id2 = 2002;

        try {
            String hashKey = HashKey.getHashKey(md5, type, id1, id2, objectStr);
            HashKeyEntity hashKeyEntity = HashKey.checkHashKey(hashKey);
            print(hashKeyEntity);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 生成原生MD5 （32位字符串）
     *
     * @param str
     * @return
     */
    static String createMD5(String str) {

        MessageDigest md5 = null;
        try {
            md5 = MessageDigest.getInstance("MD5");
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }

        char[] charArray = str.toCharArray();
        byte[] byteArray = new byte[charArray.length];

        for (int i = 0; i < charArray.length; i++) {
            byteArray[i] = (byte) charArray[i];
        }
        byte[] md5Bytes = md5.digest(byteArray);

        StringBuffer hexValue = new StringBuffer();
        for (int i = 0; i < md5Bytes.length; i++) {

            int val = ((int) md5Bytes[i]) & 0xff;
            if (val < 16) {
                hexValue.append("0");
            }
            hexValue.append(Integer.toHexString(val));
        }
        return hexValue.toString();
    }

    private static void print(Object model) {
        Class cls = model.getClass();
        Field[] fields = cls.getDeclaredFields();
        System.out.println("###### " + model.getClass().getName() + " ######");
        for (Field field : fields) {
            char[] buffer = field.getName().toCharArray();
            buffer[0] = Character.toUpperCase(buffer[0]);
            String mothodName = "get" + new String(buffer);
            try {
                Method method = cls.getDeclaredMethod(mothodName);
                Object resutl = method.invoke(model, null);
                System.out.println(field.getName() + ": " + resutl);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        System.out.println("####################### End #####################");
    }
}
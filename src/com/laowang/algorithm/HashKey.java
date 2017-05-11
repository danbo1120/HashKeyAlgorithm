package com.laowang.algorithm;

/**
 * Hash加密串码
 *
 * @author danbo
 * @date 2017年5月11日 上午9:59:20
 */
public class HashKey {

    /**
     * 安全码,长度16位字符串
     */
    private static final String secretKey = "abcdfghijklmnopq";
    /**
     * 本算法版本
     */
    private static final int version = 1;
    /**
     * 本算法允许输入字节长度38
     */
    private static final byte size = 38;

    /**
     * 生成编码HashKey
     *
     * @param md5       objectStr md5值
     * @param type      编码类型
     * @param id1       long型id1
     * @param id2       long型id2
     * @param objectStr 长度为24的字符串
     * @return
     * @throws Exception
     */
    public static String getHashKey(String md5, int type, long id1, long id2, String objectStr)
            throws Exception {
        byte[] keyBytes = new byte[size];//
        byte hashBytes[];// 16
        byte hashKeyBytes[];

        // 第一个字节存储版本号
        keyBytes[0] = (byte) (version * 32);

        // 第二个字节为文件类型
        keyBytes[1] = (byte) (type * 16);

        //规范化md5,转化为bytes型
        hashBytes = str2bytes(splitStr(md5, 16));
        if (hashBytes == null) {
            //转换失败,非hash码
            return null;
        }
        hashKeyBytes = makeHashCheck(hashBytes, 2);
        // 将keyBytes的头两个字节与自身2字节的hash校验码进行异或操作
        keyBytes[0] = (byte) (keyBytes[0] ^ hashKeyBytes[0]);
        keyBytes[1] = (byte) (keyBytes[1] ^ hashKeyBytes[1]);

        for (int i = 0; i < hashBytes.length; i++) {// 16
            char tmpChar = secretKey.charAt(i);
            byte xorByte = (byte) tmpChar;
            keyBytes[i + 2] = (byte) (xorByte ^ hashBytes[i]);
        }

        //获取hash字节码前4位校验码
        hashKeyBytes = makeHashCheck(hashBytes, 4);
        // 18-21字节存储id1
        keyBytes[18] = (byte) ((id1 & 0xFF000000) / 0x1000000 & 0xFF);
        keyBytes[19] = (byte) ((id1 & 0xFF0000) / 0x10000 & 0xFF);
        keyBytes[20] = (byte) ((id1 & 0xFF00) / 0x100 & 0xFF);
        keyBytes[21] = (byte) (id1 & 0xFF);
        // 将keyBytes的id1,数据区4个字节的数据与自身md5前四个字节的倒序进行异或处理
        for (int i = 18; i <= 21; i++) {
            keyBytes[i] = (byte) (keyBytes[i] ^ hashKeyBytes[21 - i]);
        }

        // 22-25字节存储id2
        keyBytes[22] = (byte) ((id2 & 0xFF000000) / 0x1000000 & 0xFF);
        keyBytes[23] = (byte) ((id2 & 0xFF0000) / 0x10000 & 0xFF);
        keyBytes[24] = (byte) ((id2 & 0xFF00) / 0x100 & 0xFF);
        keyBytes[25] = (byte) (id2 & 0xFF);
        // 将keyBytes的id2,数据区4个字节的数据与自身md5地址前四个字节的倒序进行异或处理
        for (int i = 22; i <= 25; i++) {
            keyBytes[i] = (byte) (keyBytes[i] ^ hashKeyBytes[25 - i]);
        }

        // 剩余字节存储objectStr
        byte[] objectBytes = str2bytes(splitStr(objectStr, 12));
        for (int i = 0; i < objectBytes.length; i++) {
            keyBytes[26 + i] = objectBytes[i];
        }
        //Base64转换为可识别字符串(长度为51的字符串)
        return SafeBase64.encode(keyBytes);
    }

    /**
     * 校验该HashKey
     *
     * @param hashKey
     * @return HashKeyEntity
     * @throws Exception
     */
    public static HashKeyEntity checkHashKey(String hashKey) throws Exception {
        // 结果集
        byte allBytes[];
        // hash校验码
        byte checkBytes[];

        //hashKey长度为51
        if (hashKey.length() != 51) {
            return null;
        }

        //md5版须符合SafeBase64编码规范
        if (!SafeBase64.checkBase64Char(hashKey)) {
            return null;
        }

        // 还原出该hashKey版的bytes
        allBytes = SafeBase64.decode(hashKey);

        //hash
        byte[] hashBytes = new byte[16];
        // 进行异或操作可得出hash值(下标2-17)
        for (int i = 0; i < secretKey.length(); i++) {
            hashBytes[i] = (byte) (allBytes[i + 2] ^ secretKey.charAt(i));
        }

        // 将两个字节与自身2字节的mac地址校验码进行异或
        checkBytes = makeHashCheck(hashBytes, 2);

        allBytes[0] = (byte) (allBytes[0] ^ checkBytes[0]);
        allBytes[1] = (byte) (allBytes[1] ^ checkBytes[1]);

        // 第一个字节的高3位是协议版本号
        byte version = (byte) ((allBytes[0]) / 32);

        // 目前支持协议版本号1
        if (version != 1) {
            return null;
        }

        // 第二个字节首4位是内容类型,目前支持1-15
        byte type = (byte) ((allBytes[1] & 0xf0) / 16);
        if (type < 1 || type > 15) {
            return null;
        }

        checkBytes = makeHashCheck(hashBytes, 4);
        // 下标17-20共4个字节与自身MAC地址的倒序进行异或操作得出id1数据区
        for (int i = 18; i <= 21; i++) {
            allBytes[i] = (byte) (allBytes[i] ^ checkBytes[21 - i]);
        }
        long id1 = (byte2Int(allBytes[18]) * 16777216 + byte2Int(allBytes[19]) * 65536 + byte2Int(allBytes[20]) * 256
                + byte2Int(allBytes[21]));

        // 下标21-24共4个字节与自身MAC地址的倒序进行异或操作得出collectionId数据区
        for (int i = 22; i <= 25; i++) {
            allBytes[i] = (byte) (allBytes[i] ^ checkBytes[25 - i]);
        }
        long id2 = (byte2Int(allBytes[22]) * 16777216 + byte2Int(allBytes[23]) * 65536
                + byte2Int(allBytes[24]) * 256 + byte2Int(allBytes[25]));

        //剩余字节为objectString
        byte[] objectBytes = new byte[12];
        for (int i = 0; i < objectBytes.length; i++) {
            objectBytes[i] = allBytes[26 + i];
        }

        HashKeyEntity hashKeyEntity = new HashKeyEntity();
        hashKeyEntity.setHashKey(hashKey);
        hashKeyEntity.setVersion(version);
        hashKeyEntity.setType(type);
        hashKeyEntity.setHash(getString(hashBytes));
        hashKeyEntity.setId1(id1);
        hashKeyEntity.setId2(id2);
        hashKeyEntity.setObjectStr(getString(objectBytes));

        return hashKeyEntity;
    }

    private static int byte2Int(byte b) {
        if (b < 0) {
            return 256 + b;
        } else {
            return b;
        }
    }

    /**
     * 将size位的string值按照每两个字符分割
     *
     * @param md5(必须32字符)
     * @return
     */
    private static String[] splitStr(String md5, int size) {
        String[] result = new String[size];
        for (int i = 0; i < size; i++) {
            String s = md5.substring(i * 2, i * 2 + 2);
            result[i] = s;
        }
        return result;
    }

    /**
     * 每两个个字符转位十六进制数
     *
     * @param str
     * @return
     */
    private static byte[] str2bytes(String[] str) {
        byte[] tagbyte = new byte[str.length];
        char a1;
        char a2;
        for (int i = 0; i < str.length; i++) {
            if (str[i].length() != 2) {
                return null;
            }
            a1 = str[i].charAt(0);
            a2 = str[i].charAt(1);
            a1 -= 48;

            if (a1 >= 17 && a1 <= 22) {
                a1 -= 7;
            }
            if (a1 >= 49 && a1 <= 54) {
                a1 -= 39;
            }
            if (a1 < 0 || a1 > 15) {
                return null;
            }

            a2 -= 48;
            if (a2 >= 17 && a2 <= 22) {
                a2 -= 7;
            }
            if (a2 >= 49 && a2 <= 54) {
                a2 -= 39;
            }
            if (a2 < 0 || a2 > 15) {
                return null;
            }
            tagbyte[i] = (byte) (a1 * 16 + a2);
        }
        return tagbyte;
    }

    /**
     * 单个byte转一个16进制数(两个字符(0-15))
     *
     * @param b
     * @return
     */
    private static String bytes2HexStr(byte b) {
        String ret = "";
        String hex = Integer.toHexString(b & 0xFF);
        if (hex.length() == 1) {
            hex = '0' + hex;
        }
        ret += hex.toLowerCase();

        return ret;
    }

    /**
     * byte转string
     */
    private static String getString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            sb.append(bytes2HexStr(bytes[i]));
        }
        return sb.toString();
    }

    /**
     * 对inputByte的前byteCount为生成hash校验码
     *
     * @param inputByte 输入字节
     * @param byteCount 校验位
     * @return
     */
    private static byte[] makeHashCheck(byte[] inputByte, int byteCount) {
        byte[] returnByte = new byte[byteCount];
        byte[] tagByte = new byte[inputByte.length];// 7
        int nowBound;
        int i, j;
        for (i = 0; i < inputByte.length; i++) {
            tagByte[i] = inputByte[i];
        }
        nowBound = tagByte.length - 1;
        for (j = nowBound; j >= byteCount; j--) {
            for (i = 0; i <= j - 1; i++) {
                tagByte[i] = (byte) (tagByte[i] ^ tagByte[i + 1]);
            }
        }
        for (i = 0; i < byteCount; i++) {
            returnByte[i] = tagByte[i];
        }
        return returnByte;
    }
}

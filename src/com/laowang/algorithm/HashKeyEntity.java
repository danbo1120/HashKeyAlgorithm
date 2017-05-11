package com.laowang.algorithm;

public class HashKeyEntity {
    private String hashKey;

    private byte version = 1;
    private byte type;

    private long id1;
    private long id2;

    private String hash;
    //长度限制24位
    private String objectStr;

    public String getHashKey() {
        return hashKey;
    }

    public void setHashKey(String hashKey) {
        this.hashKey = hashKey;
    }

    public byte getVersion() {
        return version;
    }

    public void setVersion(byte version) {
        this.version = version;
    }

    public byte getType() {
        return type;
    }

    public void setType(byte type) {
        this.type = type;
    }

    public long getId1() {
        return id1;
    }

    public void setId1(long id1) {
        this.id1 = id1;
    }

    public long getId2() {
        return id2;
    }

    public void setId2(long id2) {
        this.id2 = id2;
    }

    public String getHash() {
        return hash;
    }

    public void setHash(String hash) {
        this.hash = hash;
    }

    public String getObjectStr() {
        return objectStr;
    }

    public void setObjectStr(String objectStr) {
        this.objectStr = objectStr;
    }
}
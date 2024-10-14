package com.SM2.demo.DTO;

public class Key {
    public String PrivateKey;
    public String PublicKey_x;
    public String PublicKey_y;

    public String getPrivateKey() {
        return PrivateKey;
    }

    public void setPrivateKey(String privateKey) {
        PrivateKey = privateKey;
    }

    public String getPublicKey_x() {
        return PublicKey_x;
    }

    public void setPublicKey_x(String publicKey_x) {
        PublicKey_x = publicKey_x;
    }

    public String getPublicKey_y() {
        return PublicKey_y;
    }

    public void setPublicKey_y(String publicKey_y) {
        this.PublicKey_y = publicKey_y;
    }
}

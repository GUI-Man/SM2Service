package com.SM2.demo.SM2_5GAKATools;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

public class HN {
    AsymmetricCipherKeyPair HN;

    public ECPublicKeyParameters getPTP() {
        return PTP;
    }

    public void setPTP(ECPublicKeyParameters PTP) {
        this.PTP = PTP;
    }

    public ECPublicKeyParameters getPSN() {
        return PSN;
    }

    public void setPSN(ECPublicKeyParameters PSN) {
        this.PSN = PSN;
    }

    public ECPublicKeyParameters getPUE() {
        return PUE;
    }

    public void setPUE(ECPublicKeyParameters PUE) {
        this.PUE = PUE;
    }

    public AsymmetricCipherKeyPair getHN() {
        return HN;
    }

    public void setHN(AsymmetricCipherKeyPair HN) {
        this.HN = HN;
    }

    ECPublicKeyParameters PUE;
    ECPublicKeyParameters PSN;
    ECPublicKeyParameters PTP;
    SM2 sm2;

}

package com.SM2.demo.Service;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.Security;

public class SM2_Generator {
    static BigInteger SM2_ECC_P = new BigInteger("8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3", 16); //素数域
    static BigInteger SM2_ECC_A = new BigInteger("787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498", 16); //曲线系数a
    static BigInteger SM2_ECC_B = new BigInteger("63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A", 16); //曲线系数b
    static BigInteger SM2_ECC_N = new BigInteger("8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7", 16); //生成元G的阶数
    static BigInteger SM2_ECC_H = ECConstants.ONE;                                  //余因子为1
    static BigInteger SM2_ECC_GX = new BigInteger("421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D", 16); //生成元x坐标
    static BigInteger SM2_ECC_GY = new BigInteger("0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2", 16); //生成元x坐标
    private static ECDomainParameters domainParams=null;
    static {
        //    Java中，安全提供者（Security Provider）是一种实现了特定安全服务的软件模块。它提供了一系列的加密、解密、签名、验证和随机数生成等安全功能。安全提供者基础设施在Java中的作用是为开发人员提供一种扩展和替换标准安全功能的方式，以满足特定的安全需求。
//    Java的安全提供者基础设施是通过Java Cryptography Architecture（JCA）实现的。JCA定义了一组API和框架，用于在Java平台上实现各种安全服务。安全提供者是JCA的核心组件之一，它通过实现JCA规范中定义的接口，向应用程序提供安全功能。
//    安全提供者可以由Java平台提供的默认提供者，也可以是第三方开发的提供者。默认提供者包含在Java开发工具包（JDK）中，并提供了一些常见的加密算法和安全功能。第三方提供者则可以通过扩展JCA接口，实现自定义的加密算法和其他安全功能。
//    使用安全提供者，开发人员可以在应用程序中轻松地切换和配置不同的安全实现。例如，可以根据具体的安全需求选择不同的提供者，或者通过配置文件动态加载和替换提供者。这种灵活性使得Java应用程序能够适应不同的安全环境和要求。
//    总之，Java中的安全提供者基础设施允许开发人员使用标准或自定义的安全功能，以保护和加密数据，验证身份，以及执行其他与安全相关的操作。它为Java应用程序提供了一种可扩展和灵活的安全解决方案。
        Security.addProvider(new BouncyCastleProvider());
    }
    public static void getcurve()
    {
        //判断有没有参数
        if(domainParams !=null)return;
        //生成ECC曲线和G
        ECCurve curve = new ECCurve.Fp(SM2_ECC_P, SM2_ECC_A, SM2_ECC_B, SM2_ECC_N, SM2_ECC_H);
        ECPoint g = curve.createPoint(SM2_ECC_GX, SM2_ECC_GY);
        domainParams = new ECDomainParameters(curve, g, SM2_ECC_N);
//        System.out.println("你好"+domainParams.getG());
        ECPoint x=domainParams.getG();
        System.out.println("gx:"+x.getXCoord().toString());
        System.out.println("gy:"+x.getYCoord().toString());
//        System.out.println("Pause");
        return ;
    }
    public static SecureRandom Generate256SecureRandom(){
        SecureRandom secureRandom = new SecureRandom();
        byte[] randomBytes = new byte[256];
        secureRandom.nextBytes(randomBytes);
        return secureRandom;
    }
    public static AsymmetricCipherKeyPair generateKey(){
        // 构造曲线
        getcurve();
        // 实例化密钥对生成器
        ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();

        //A用户私钥6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE,这里是指定了一个指定值,事实上数字只是一个强随机数，可以替换
        ECKeyGenerationParameters aKeyGenParams = new ECKeyGenerationParameters(domainParams, SM2_Generator.Generate256SecureRandom());
        // 初始化密钥对生成器
        keyPairGenerator.init(aKeyGenParams);
        // 生成密钥对
//		KeyPair keyPair = keyPairGenerator.generateKeyPair();
        AsymmetricCipherKeyPair aKp = keyPairGenerator.generateKeyPair();
        // 甲方公钥
        //PublicKey publicKey = (PublicKey) keyPair.getPublic();
        ECPublicKeyParameters aPub = (ECPublicKeyParameters)aKp.getPublic();
        // 甲方私钥
        //PrivateKey privateKey = (PrivateKey) keyPair.getPrivate();
        ECPrivateKeyParameters aPriv = (ECPrivateKeyParameters)aKp.getPrivate();
        System.out.println("私钥:"+aPriv.getD().toString());
        System.out.println("公钥x:"+aPub.getQ().getAffineXCoord().toBigInteger().toString());
        System.out.println("公钥y:"+aPub.getQ().getAffineYCoord().toBigInteger().toString());
        ECPoint g = domainParams.getG();
        System.out.println("生成元gx:"+g.getAffineXCoord().toBigInteger().toString());
        System.out.println("生成元gy:"+g.getAffineYCoord().toBigInteger().toString());
        ECPoint Xpub = g.multiply(aPriv.getD());
        Xpub = ECAlgorithms.importPoint(Xpub.getCurve(), Xpub).normalize();
        System.out.println("生成元G*私钥D=x:"+Xpub.getAffineXCoord().toBigInteger().toString());
        System.out.println("y:"+Xpub.getAffineYCoord().toBigInteger().toString());

        return aKp;

    }
}

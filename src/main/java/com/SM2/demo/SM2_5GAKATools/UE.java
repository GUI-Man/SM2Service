package com.SM2.demo.SM2_5GAKATools;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.sql.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class UE {
    AsymmetricCipherKeyPair A;
    AsymmetricCipherKeyPair B;
    AsymmetricCipherKeyPair UE;
    ECPublicKeyParameters PHN;
    ECPublicKeyParameters PSN;
    ECPublicKeyParameters PTP;
    SM2 sm2;
    byte[] RID;
    byte[] AID_1;
    byte[] AID_2;
    long timeStamp;

    public long getTimeStamp() {
        return timeStamp;
    }

    public void setTimeStamp(long timeStamp) {
        this.timeStamp = timeStamp;
    }

    public byte[] getAID_1() {
        return AID_1;
    }

    public void setAID_1(byte[] AID_1) {
        this.AID_1 = AID_1;
    }

    public byte[] getAID_2() {
        return AID_2;
    }

    public void setAID_2(byte[] AID_2) {
        this.AID_2 = AID_2;
    }

    public byte[] getRID() {
        return RID;
    }

    public void setRID(byte[] RID) {
        this.RID = RID;
    }

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

    public ECPublicKeyParameters getPHN() {
        return PHN;
    }

    public void setPHN(ECPublicKeyParameters PHN) {
        this.PHN = PHN;
    }

    public AsymmetricCipherKeyPair getUE() {
        return UE;
    }

    public void setUE(AsymmetricCipherKeyPair UE) {
        this.UE = UE;
    }

    public AsymmetricCipherKeyPair getB() {
        return B;
    }

    public void setB(AsymmetricCipherKeyPair b) {
        B = b;
    }

    public AsymmetricCipherKeyPair getA() {
        return A;
    }

    public void setA(AsymmetricCipherKeyPair a) {
        A = a;
    }
    public UE() throws SQLException,ClassNotFoundException{
        this.sm2=new SM2();
        byte[] UEPUBbyte;
        byte[] UEPrivByte;
        byte[] SNPUBbyte;
        byte[] TPPUBbyte;
        byte[] HNPUBByte;
        Map<String, Object> sqlmap = autoSqlValue();
        UEPUBbyte= Base64.getDecoder().decode((String)sqlmap.get("UEPub"));
        UEPrivByte=Base64.getDecoder().decode((String)sqlmap.get("UEPRIV"));
        this.setUE(new AsymmetricCipherKeyPair(sm2.RestorePub(UEPUBbyte),sm2.RestorePriv(new BigInteger(UEPrivByte))));
        SNPUBbyte= Base64.getDecoder().decode((String)sqlmap.get("SNPub"));
        this.setPSN(sm2.RestorePub(SNPUBbyte));
        TPPUBbyte=Base64.getDecoder().decode((String)sqlmap.get("TPPub"));
        this.setPTP(sm2.RestorePub(TPPUBbyte));
        HNPUBByte=Base64.getDecoder().decode((String)sqlmap.get("HNPub"));
        this.setPHN(sm2.RestorePub(HNPUBByte));

    }
    public Map<String,Object> autoSqlValue() throws ClassNotFoundException, SQLException{
        Class.forName("com.mysql.jdbc.Driver");
        Connection con= DriverManager.getConnection("jdbc:mysql://localhost:3306/test","root","123456");
        PreparedStatement ps=con.prepareStatement("select * from UE where id=1 ");
        ResultSet rs = ps.executeQuery();
        ResultSetMetaData metaData = rs.getMetaData();
        int columnCount=metaData.getColumnCount();
        Map<String,Object> columnValues=new HashMap<>();
        while(rs.next()) {
            for (int i = 1; i <= columnCount; i++) {
                String columnName = metaData.getColumnName(i);
                Object columnValue = rs.getObject(i);
                columnValues.put(columnName, columnValue);
            }
        }
//        while(rs.next()) {
//
//            System.out.println(rs.getString("UEPUB"));
//        }
        rs.close();
        con.close();

        return columnValues;
    }
    public void gen_key() throws ClassNotFoundException, SQLException {
        this.sm2 = new SM2();
        Class.forName("com.mysql.jdbc.Driver");
        //生成一个65字节长度的RID
        this.RID=sm2.generateByteStream(65);
        Connection con= DriverManager.getConnection("jdbc:mysql://localhost:3306/test","root","123456");

        PreparedStatement ps = con.prepareStatement("UPDATE UE set RID=\"" + this.RID + "\" where id=1;");
        con.close();
    }
    //UE请求凭证
    public void ask() throws Exception{
        //1步骤,算出C
        Connection con= DriverManager.getConnection("jdbc:mysql://localhost:3306/test","root","123456");
        this.RID=sm2.generateByteStream(65);

        AsymmetricCipherKeyPair temp = this.sm2.generateKey();
        //C的点的公共值
        ECPublicKeyParameters CPublic = (ECPublicKeyParameters)temp.getPublic();

        byte[] Cor = CPublic.getQ().getEncoded(false);
        //2步骤，计算中间值M
        byte[] M=SM2.xorByteArrays(Cor,RID);
        //3.选取两个随机数a,b计算A,B
        A=this.sm2.generateKey();
        B=this.sm2.generateKey();
        //4.计算两个假名
        ECCurve.Fp curve = this.sm2.getcurve();
        ECPrivateKeyParameters aPrivate = (ECPrivateKeyParameters) A.getPrivate();
        ECPrivateKeyParameters bPrivate = (ECPrivateKeyParameters) B.getPrivate();
        ECPublicKeyParameters aPublic = (ECPublicKeyParameters)A.getPublic();
        ECPublicKeyParameters bPublic = (ECPublicKeyParameters)B.getPublic();
        BigInteger aPrivBG = aPrivate.getD();
        BigInteger bPrivBG= bPrivate.getD();
//a*Ktp和b*Phn
        ECPoint amultiplyTPtemp = this.PTP.getQ().multiply(aPrivBG);
        ECPoint bmultiplyHNtemp = this.PHN.getQ().multiply(bPrivBG);
        byte[] Hktp = SM3.extendHash(amultiplyTPtemp.getEncoded(false), 65);
        byte[] Hkhn = SM3.extendHash(bmultiplyHNtemp.getEncoded(false),65);
        byte[] AID_1=SM2.xorByteArrays(M,Hktp);
        this.setAID_1(AID_1);

        byte[] AID_2=SM2.xorByteArrays(Cor,Hkhn);
        this.setAID_2(AID_2);
        //第五步：UE向TP和HN分别请求身份凭证
        //生成时间戳签名

        PreparedStatement ps=con.prepareStatement("UPDATE UE set AID_1=\""+Base64.getEncoder().encodeToString(this.AID_1)+"\" where id=1;");
        ps.execute();
        ps=con.prepareStatement("UPDATE UE set AID_2=\""+Base64.getEncoder().encodeToString(this.AID_2)+"\" where id=1;");
        ps.execute();

        // 获取当前时间的时间戳（毫秒）
        long timestamp = System.currentTimeMillis();
        this.setTimeStamp(timestamp);
        ps=con.prepareStatement("UPDATE UE set TimeSTAMP="+this.timeStamp+" where id=1;");
        ps.execute();
        byte[] timestampByte=SM2.longToBytes(timestamp);
        byte[] SignData1=SM2.byteMerger(AID_1,timestampByte,aPublic.getQ().getEncoded(false));
        byte[] SignData2=SM2.byteMerger(AID_2,timestampByte,bPublic.getQ().getEncoded(false));
        SM2sign sm2sign = new SM2sign();
        byte[] sign1 = sm2sign.sign(this.UE.getPrivate(), null, SignData1);
        byte[] sign2 = sm2sign.sign(this.UE.getPrivate(), null, SignData2);

        //向TP发送的内容
        ps=con.prepareStatement("UPDATE TP set TimeSTAMPUE="+this.timeStamp+" where id=1;");
        ps.execute();
        ps=con.prepareStatement("UPDATE TP set AID_1=\""+Base64.getEncoder().encodeToString(this.AID_1)+"\" where id=1;");
        ps.execute();
        String AString = Base64.getEncoder().encodeToString(aPublic.getQ().getEncoded(false));
        ps=con.prepareStatement("UPDATE TP set A=\""+AString+"\" where id=1;");
        ps.execute();
        ps=con.prepareStatement("UPDATE TP set SIGNDATA=\""+Base64.getEncoder().encodeToString(sign1)+"\" where id=1;");
        ps.execute();

        //向HN发送的内容
        ps=con.prepareStatement("UPDATE HN set TimeSTAMPUE="+this.timeStamp+" where id=1;");
        ps.execute();
        ps=con.prepareStatement("UPDATE HN set AID_2=\""+Base64.getEncoder().encodeToString(this.AID_2)+"\" where id=1;");
        ps.execute();
        String BString = Base64.getEncoder().encodeToString(bPublic.getQ().getEncoded(false));
        ps=con.prepareStatement("UPDATE HN set B=\""+BString+"\" where id=1;");
        ps.execute();
        ps=con.prepareStatement("UPDATE HN set SIGNDATA=\""+Base64.getEncoder().encodeToString(sign2)+"\" where id=1;");
        ps.execute();

        ps.close();
        con.close();
    }

    public void updateTime() throws SQLException,ClassNotFoundException{
        long time=System.currentTimeMillis();
        Connection con= DriverManager.getConnection("jdbc:mysql://localhost:3306/test","root","123456");

        PreparedStatement ps = con.prepareStatement("UPDATE HN set TimeSTAMPUE=" + time + " where id=1;");
        ps.execute();
        ps = con.prepareStatement("UPDATE UE set TimeSTAMP=" + time + " where id=1;");
        ps.execute();
        ps = con.prepareStatement("UPDATE TP set TimeSTAMPUE=" + time + " where id=1;");
        ps.execute();


    }
//    private String SUPI;
//    public KeyPair K;
//    public String getSUPI() {
//        return SUPI;
//    }
//    // 通用哈希算法函数
//    private static String hashUsingAlgorithm(String input, String algorithm) {
//        try {
//            // 使用指定算法创建MessageDigest实例
//            MessageDigest digest = MessageDigest.getInstance(algorithm, "BC");
//
//            // 将输入字符串转换为字节数组并计算哈希值
//            byte[] hashBytes = digest.digest(input.getBytes());
//
//            // 将哈希值转换为十六进制字符串
//            return Hex.toHexString(hashBytes);
//        } catch (NoSuchAlgorithmException e) {
//            throw new RuntimeException("Error: Unsupported algorithm " + algorithm, e);
//        } catch (NoSuchProviderException e) {
//            throw new RuntimeException(e);
//        }
//    }
//    //f1使用SHA-512生成
//    public String f1(String input){
//        return hashUsingAlgorithm(input, "SHA-512");
//    }
//    //f2使用SM3生成
//    public String f2(String input){
//        return hashUsingAlgorithm(input, "SM3");
//    }
//
//    public void setSUPI(String SUPI) {
//        this.SUPI = SUPI;
//    }
//    public void generateSUPI(){
//        this.SUPI= String.valueOf(UUID.randomUUID()).substring(0,15);
//    }
//
//    public String generate_MAC(byte[] K,byte[] SQNHE,byte[] RAND){
//        return "sdf";
//    }
//    public String generate_SUCI(String S1,String S2){
//        AsymmetricCipherKeyPair tempKeyPair = SM2.generateKey();
//        byte[] KE=SM2.KDF(S1,256);
//        //由于这里暂时不知道KM是怎么来的，所以决定先用一个随机比特代替它
//        // 创建一个SecureRandom实例
//        SecureRandom secureRandom = new SecureRandom();
//
//        // 创建一个长度为32字节的byte数组 (256比特)
//        byte[] Km = new byte[32];
//
//        // 使用SecureRandom生成随机字节
//        secureRandom.nextBytes(Km);
//        return "SUCI";
//    }

//    public void Init_Protocol(){
//        System.out.println("开始初始化");
//
//    }
}

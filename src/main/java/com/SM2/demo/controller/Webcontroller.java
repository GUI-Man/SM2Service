package com.SM2.demo.controller;

import com.SM2.demo.DTO.Key;
import com.SM2.demo.DTO.TPDTO;
import com.SM2.demo.DTO.UEDTO;
import com.SM2.demo.Response;
import com.SM2.demo.SM2_5GAKATools.*;
import com.SM2.demo.Service.SM2_Generator;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.hibernate.annotations.processing.SQL;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.math.BigInteger;
import java.sql.*;
import java.util.Base64;

import static com.SM2.demo.SM2_5GAKATools.SM2.generateByteStream;

@RestController
public class Webcontroller {
    @GetMapping("/ue/{id}")
    public Response<String> getStudentById(@PathVariable long id){
        return Response.newSuccess("UE_Service.getStudentById(id)");
    }
    // 使用@PostMapping
    @PostMapping("/test")
    public ResponseEntity<String> submitData(@RequestBody String data) {
        // 处理数据...
        return ResponseEntity.ok("Data received: " + data);
    }
    @PostMapping("/initALL")
    public ResponseEntity<String> Init(@RequestParam(name = "password",required = true) String password) throws ClassNotFoundException, SQLException {
        Class.forName("com.mysql.jdbc.Driver");

        Connection con= DriverManager.getConnection("jdbc:mysql://localhost:3306/test","root","123456");
        byte[] bytes = generateByteStream(15);
        String encode = Base64.getEncoder().encodeToString(bytes);

        System.out.println(password);
        PreparedStatement ps=con.prepareStatement("insert into BASE64Test (Encode) value ('"+encode+"')");
        ps.execute();
        ps=con.prepareStatement("select AdPASS from password");

        ResultSet rs=  ps.executeQuery();
        String ADpass = "";
        while(rs.next()) {
            ADpass = rs.getString("AdPASS");

        }
        if(ADpass.equals(password)){
            //生成全部的公私钥对
            SM2 sm2 = new SM2();
            AsymmetricCipherKeyPair HNKey = sm2.generateKey();
            AsymmetricCipherKeyPair SNKey = sm2.generateKey();
            AsymmetricCipherKeyPair TPKey=sm2.generateKey();
            AsymmetricCipherKeyPair UEKey=sm2.generateKey();
            ECPublicKeyParameters HNPub = (ECPublicKeyParameters)HNKey.getPublic();
            ECPrivateKeyParameters HNPriv=(ECPrivateKeyParameters) HNKey.getPrivate();
            ECPublicKeyParameters SNPub = (ECPublicKeyParameters)SNKey.getPublic();
            ECPrivateKeyParameters SNPriv=(ECPrivateKeyParameters) SNKey.getPrivate();
            ECPublicKeyParameters UEPub = (ECPublicKeyParameters)UEKey.getPublic();
            ECPrivateKeyParameters UEPriv=(ECPrivateKeyParameters) UEKey.getPrivate();
            ECPublicKeyParameters TPPub = (ECPublicKeyParameters)TPKey.getPublic();
            ECPrivateKeyParameters TPPriv=(ECPrivateKeyParameters) TPKey.getPrivate();
            byte[] hnPub = HNPub.getQ().getEncoded(false);
            String hnPubStore=Base64.getEncoder().encodeToString(hnPub);
            String hnPrivStore=Base64.getEncoder().encodeToString(HNPriv.getD().toByteArray());
            String snPubStore=Base64.getEncoder().encodeToString(SNPub.getQ().getEncoded(false));
            String snPrivStore=Base64.getEncoder().encodeToString(SNPriv.getD().toByteArray());
            String uePubStore=Base64.getEncoder().encodeToString(UEPub.getQ().getEncoded(false));
            String uePrivStore=Base64.getEncoder().encodeToString(UEPriv.getD().toByteArray());
            String tpPubStore=Base64.getEncoder().encodeToString(TPPub.getQ().getEncoded(false));
            String tpPrivStore=Base64.getEncoder().encodeToString(TPPriv.getD().toByteArray());
            //清空过去用过的表格，每个机器里面应该都只有一个数据
            ps=con.prepareStatement("DELETE FROM UE WHERE 1=1;");
            ps.execute();
            ps=con.prepareStatement("DELETE FROM SN WHERE 1=1;");
            ps.execute();
            ps=con.prepareStatement("DELETE FROM TP WHERE 1=1;");
            ps.execute();
            ps=con.prepareStatement("DELETE FROM HN WHERE 1=1;");
            ps.execute();
            ps=con.prepareStatement("insert into UE(id,TPPub,HNPub, UEPRIV, UEPUB, SNPUB) VALUES (1,'"+tpPubStore
            +"','"+hnPubStore+"','"+uePrivStore+"','"+uePubStore+"','"+snPubStore+"')");
            ps.execute();
            ps=con.prepareStatement("insert into HN(id,TPPub,HNPub, HNPRIV, UEPUB, SNPUB) VALUES (1,'"+tpPubStore
                    +"','"+hnPubStore+"','"+hnPrivStore+"','"+uePubStore+"','"+snPubStore+"')");
            ps.execute();
            ps=con.prepareStatement("insert into SN(id,TPPub,HNPub, SNPRIV, UEPUB, SNPUB) VALUES (1,'"+tpPubStore
                    +"','"+hnPubStore+"','"+snPrivStore+"','"+uePubStore+"','"+snPubStore+"')");
            ps.execute();
            ps=con.prepareStatement("insert into TP(id,TPPub,HNPub, TPPRIV, UEPUB, SNPUB) VALUES (1,'"+tpPubStore
                    +"','"+hnPubStore+"','"+tpPrivStore+"','"+uePubStore+"','"+snPubStore+"')");
            ps.execute();

            con.close();
            rs.close();
            return ResponseEntity.ok("Accepted");
        }
        else{
            con.close();
            rs.close();
            return ResponseEntity.ok("password:"+password+"is Failure");
        }
    }
    @GetMapping("/generate_Key")
    public Response<Key> getStudentById(){
        AsymmetricCipherKeyPair asymmetricCipherKeyPair = SM2_Generator.generateKey();
        Key key = new Key();
        String privateKey=((ECPrivateKeyParameters)asymmetricCipherKeyPair.getPrivate()).getD().toString();
        String publicKeyX=((ECPublicKeyParameters)asymmetricCipherKeyPair.getPublic()).getQ().getAffineXCoord().toString();
        String publicKeyY=((ECPublicKeyParameters)asymmetricCipherKeyPair.getPublic()).getQ().getAffineYCoord().toString();
        key.setPrivateKey(privateKey);
        key.setPublicKey_x(publicKeyX);
        key.setPublicKey_y(publicKeyY);
        return Response.newSuccess(key);
    }
    @GetMapping("/getUeINFO2")
    public Response<UEDTO> getUeParams2() throws Exception{

        UEDTO uedto = new UEDTO();
        UE ue=new UE();
        ue.gen_key();
        ue.ask();
        byte[] aid1 = ue.getAID_1();
        byte[] aid2 = ue.getAID_2();
        byte[] rid = ue.getRID();
        String AID_1 = Base64.getEncoder().encodeToString(aid1);
        String AID_2 =Base64.getEncoder().encodeToString(aid2);
        String RID=Base64.getEncoder().encodeToString(rid);
        AsymmetricCipherKeyPair ue1 = ue.getUE();

        String UEprivateKey=(((ECPrivateKeyParameters)ue1.getPrivate()).getD().toString());
        ECPublicKeyParameters ue1Public = (ECPublicKeyParameters) ue1.getPublic();

        String UEPublicKeyx=(ue1Public.getQ().getAffineXCoord().toString());
        String UEPublicKeyy=(ue1Public.getQ().getAffineYCoord().toString());

        uedto.setAID_1Base64(AID_1);
        uedto.setAID_2Base64(AID_2);
        uedto.setUEPriv(UEprivateKey);
        uedto.setUEPubx(UEPublicKeyx);
        uedto.setUEPuby(UEPublicKeyy);
        uedto.setHNPubx(ue.getPHN().getQ().getAffineXCoord().toString());
        uedto.setHNPuby(ue.getPHN().getQ().getAffineYCoord().toString());
        uedto.setTPPubx(ue.getPTP().getQ().getAffineXCoord().toString());
        uedto.setTPPuby(ue.getPTP().getQ().getAffineYCoord().toString());
        uedto.setSNPubx(ue.getPSN().getQ().getAffineXCoord().toString());
        uedto.setSNPuby(ue.getPSN().getQ().getAffineYCoord().toString());
        uedto.setRIDBase64(RID);
        uedto.setTimestamp(ue.getTimeStamp());
        return Response.newSuccess(uedto);
    }
@GetMapping("/generate_TPAllinfo")
public Response<TPDTO> getTPParams() throws Exception {

    TPDTO tpdto = new TPDTO();
    TP tp=new TP();

    byte[] aid1 = tp.getAID_1();
//    String AID_1 = Base64.getEncoder().encodeToString(aid1);
    AsymmetricCipherKeyPair tp1 = tp.getTP();

    String TPprivateKey=(((ECPrivateKeyParameters)tp1.getPrivate()).getD().toString());
    ECPublicKeyParameters tp1Public = (ECPublicKeyParameters) tp1.getPublic();

    String TPPublicKeyx=(tp1Public.getQ().getAffineXCoord().toString());
    String TPPublicKeyy=(tp1Public.getQ().getAffineYCoord().toString());

//    tpdto.setAID_1Base64(AID_1);
    tpdto.setTPPriv(TPprivateKey);
    tpdto.setTPPubx(TPPublicKeyx);
    tpdto.setTPPuby(TPPublicKeyy);
    tpdto.setHNPubx(tp.getPHN().getQ().getAffineXCoord().toString());
    tpdto.setHNPuby(tp.getPHN().getQ().getAffineYCoord().toString());
    tpdto.setUEPubx(tp.getPUE().getQ().getAffineXCoord().toString());
    tpdto.setUEPuby(tp.getPUE().getQ().getAffineYCoord().toString());
    tpdto.setSNPubx(tp.getPSN().getQ().getAffineXCoord().toString());
    tpdto.setSNPuby(tp.getPSN().getQ().getAffineYCoord().toString());

    tpdto.setTimestamp(tp.getTimestamp());
    return Response.newSuccess(tpdto);
}
    @GetMapping("/generate_UEAllinfo")
    public Response<UEDTO> getUeParams() throws Exception{

        UEDTO uedto = new UEDTO();
        UE ue=new UE();
        ue.gen_key();
        //ue.ask();
        //byte[] aid1 = ue.getAID_1();
        //byte[] aid2 = ue.getAID_2();
        //byte[] rid = ue.getRID();
        //String AID_1 = Base64.getEncoder().encodeToString(aid1);
        //String AID_2 =Base64.getEncoder().encodeToString(aid2);
        //String RID=Base64.getEncoder().encodeToString(rid);
        AsymmetricCipherKeyPair ue1 = ue.getUE();

        String UEprivateKey=(((ECPrivateKeyParameters)ue1.getPrivate()).getD().toString());
        ECPublicKeyParameters ue1Public = (ECPublicKeyParameters) ue1.getPublic();

        String UEPublicKeyx=(ue1Public.getQ().getAffineXCoord().toString());
        String UEPublicKeyy=(ue1Public.getQ().getAffineYCoord().toString());

        //uedto.setAID_1Base64(AID_1);
        //uedto.setAID_2Base64(AID_2);
        uedto.setUEPriv(UEprivateKey);
        uedto.setUEPubx(UEPublicKeyx);
        uedto.setUEPuby(UEPublicKeyy);
        uedto.setHNPubx(ue.getPHN().getQ().getAffineXCoord().toString());
        uedto.setHNPuby(ue.getPHN().getQ().getAffineYCoord().toString());
        uedto.setTPPubx(ue.getPTP().getQ().getAffineXCoord().toString());
        uedto.setTPPuby(ue.getPTP().getQ().getAffineYCoord().toString());
        uedto.setSNPubx(ue.getPSN().getQ().getAffineXCoord().toString());
        uedto.setSNPuby(ue.getPSN().getQ().getAffineYCoord().toString());
        //uedto.setRIDBase64(RID);
        uedto.setTimestamp(ue.getTimeStamp());
        return Response.newSuccess(uedto);
    }
    @GetMapping("/AskInfo")
    public Response<Boolean> AskforCertTP() throws Exception {
        UE ue=new UE();
        ue.updateTime();
        ue.ask();
        TP tp = new TP();
        return Response.newSuccess(tp.VerifySign_1());
    }
}

package com.googlecode.easyec.security.test.crypto;

import com.googlecode.easyec.security.rsa.RSAClientService;
import com.googlecode.easyec.security.rsa.RSAServerService;
import com.googlecode.easyec.security.utils.PemUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.test.context.ContextConfiguration;

import javax.annotation.Resource;
import java.io.InputStream;

import static java.security.Security.addProvider;
import static java.security.Security.getProvider;

/**
 * Created by JunJie on 6/17/16.
 */
@Ignore
@ContextConfiguration(locations = "classpath:spring/test/applicationContext-crypto.xml")
public class RSATest {

    @Resource
    private RSAClientService rsaClient;
    @Resource
    private RSAServerService rsaServer;

    static {
        if (getProvider("BC") == null) addProvider(new BouncyCastleProvider());
    }

    @Test
    public void doEncryption() throws Exception {
        InputStream in = new ClassPathResource("RSA/public.key").getInputStream();
        Object o = PemUtils.read(in);
        Assert.assertNotNull(o);

        System.out.println("Is Certificate? [" + PemUtils.isCertificate(o) + "].");
        System.out.println("Is PublicKey? [" + PemUtils.isPublicKey(o) + "].");
        System.out.println("Is KeyPair? [" + PemUtils.isKeyPair(o) + "].");
    }

    @Test
    public void testRSA() throws Exception {
        String data = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><hr:Adjustment xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:hr=\"http://www.tuogo.com.cn/xml/hr\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"><hr:Probation><hr:TotalSalary>3000.0</hr:TotalSalary><hr:BasicSalary>400.0</hr:BasicSalary><hr:LunchAllowance>100.0</hr:LunchAllowance></hr:Probation></hr:Adjustment>";
        byte[] bs = rsaServer.encryptWithPublicKey(data.getBytes("utf-8"));
        System.out.println(new String(bs, "utf-8"));

        bs = rsaServer.decryptWithPrivateKey(bs);
        System.out.println(new String(bs, "utf-8"));

        bs = rsaServer.encryptWithPrivateKey(bs);
        System.out.println(new String(bs, "utf-8"));

        bs = rsaClient.decryptWithPublicKey(bs);
        System.out.println(new String(bs, "utf-8"));
    }
}

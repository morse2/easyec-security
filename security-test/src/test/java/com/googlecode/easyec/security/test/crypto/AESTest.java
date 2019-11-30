package com.googlecode.easyec.security.test.crypto;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.Security;

import static java.security.Security.addProvider;
import static java.security.Security.getProvider;

public class AESTest {

    static {
        if (getProvider("BC") == null) addProvider(new BouncyCastleProvider());
    }

    //算法名
    public static final String KEY_ALGORITHM = "AES";
    //加解密算法/模式/填充方式
    //可以任意选择，为了方便后面与iOS端的加密解密，采用与其相同的模式与填充方式
    //ECB模式只用密钥即可对数据进行加密解密，CBC模式需要添加一个参数iv
    public static final String CIPHER_ALGORITHM = "AES/CBC/PKCS7Padding";

    //生成密钥
    public byte[] generateKey() throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        KeyGenerator keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM);
        keyGenerator.init(128);
        SecretKey key = keyGenerator.generateKey();
        return key.getEncoded();
    }

    //生成iv
    public AlgorithmParameters generateIV() throws Exception {
        //iv 为一个 16 字节的数组，这里采用和 iOS 端一样的构造方法，数据全为0
        byte[] iv = new byte[16];
        Arrays.fill(iv, (byte) 0x00);
        System.out.println(Base64.encodeBase64String(iv));
        return generateIV(iv);
    }

    //生成iv
    public AlgorithmParameters generateIV(byte[] bs) throws Exception {
        //iv 为一个 16 字节的数组，这里采用和 iOS 端一样的构造方法，数据全为0
        AlgorithmParameters params = AlgorithmParameters.getInstance(KEY_ALGORITHM);
        params.init(new IvParameterSpec(bs));
        return params;
    }

    //转化成JAVA的密钥格式
    public Key convertToKey(byte[] keyBytes) throws Exception {
        return new SecretKeySpec(keyBytes, KEY_ALGORITHM);
    }

    //加密
    public byte[] encrypt(byte[] data, byte[] keyBytes, AlgorithmParameters iv) throws Exception {
        //转化为密钥
        Key key = convertToKey(keyBytes);
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        //设置为加密模式
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return cipher.doFinal(data);
    }

    //解密
    public byte[] decrypt(byte[] encryptedData, byte[] keyBytes, AlgorithmParameters iv) throws Exception {
        Key key = convertToKey(keyBytes);
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        //设置为解密模式
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        return cipher.doFinal(encryptedData);
    }

    @Test
    public void testIt() throws Exception {
        String plainTextString = "Hello,Bouncy Castle";
        System.out.println("明文 : " + plainTextString);

        byte[] key;
        try {
            //初始化密钥
            key = generateKey();
            //初始化iv
            AlgorithmParameters iv = generateIV();
            System.out.println("密钥 : " + Base64.encodeBase64String(key));
            System.out.println("IV : " + Base64.encodeBase64String(iv.getEncoded()));

            //进行加密
            byte[] encryptedData = encrypt(plainTextString.getBytes(), key, iv);
            //输出加密后的数据
            System.out.println("加密后的数据 : " + Base64.encodeBase64String(encryptedData));

            //进行解密
            byte[] data = decrypt(encryptedData, key, iv);
            System.out.println("解密得到的数据 : " + new String(data));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Test
    public void decrypt() throws Exception {
        String text = "Lq/tBUEurqCbGleiBzrZUhX6990U7/4x964WSBnV0mc=";
        String key = "rYit9NQOagUtWjHNgzrU4A==";
        String iv = "AAAAAAAAAAAAAAAAAAAAAA==";

        byte[] decrypt = decrypt(
            Base64.decodeBase64(text),
            Base64.decodeBase64(key),
            generateIV(Base64.decodeBase64(iv))
        );
        System.out.println(new String(decrypt));
    }
}

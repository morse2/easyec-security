package com.googlecode.easyec.security.digest;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;

import javax.crypto.Cipher;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * 非对称加密算法的消息摘要类。
 *
 * @author JunJie
 */
public class RSAMessageDigest implements MessageDigest {

    private final Cipher cipher;
    private PublicKey publicKey;
    private PrivateKey privateKey;

    public RSAMessageDigest(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        cipher = Cipher.getInstance("RSA");

        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public String encrypt(String plainText) throws Exception {
        if (StringUtils.isBlank(plainText)) {
            throw new IllegalArgumentException("Plain text is null.");
        }

        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return Base64.encodeBase64String(cipher.doFinal(plainText.getBytes("utf-8")));
    }

    public String decrypt(String cipherText) throws Exception {
        if (StringUtils.isBlank(cipherText)) {
            throw new IllegalArgumentException("Cipher text is null.");
        }

        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] bs = cipher.doFinal(Base64.decodeBase64(cipherText));

        return new String(bs, "utf-8");
    }
}

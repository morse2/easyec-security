package com.googlecode.easyec.security.digest;

import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.io.ClassPathResource;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * 消息摘要工厂类。用于配置消息加解密的实现类。
 *
 * @author JunJie
 */
public class MessageDigestFactoryBean implements FactoryBean<MessageDigest>, InitializingBean {

    private MessageDigest messageDigest;

    private String jksFile;
    private String alias;
    private String storePass;
    private String algorithm;

    /**
     * 设置JKS文件路径
     *
     * @param jksFile JKS文件
     */
    public void setJksFile(String jksFile) {
        this.jksFile = jksFile;
    }

    /**
     * 设置别名
     *
     * @param alias 别名
     */
    public void setAlias(String alias) {
        this.alias = alias;
    }

    /**
     * 设置访问JKS文件的密码
     *
     * @param storePass JKS文件的密码
     */
    public void setStorePass(String storePass) {
        this.storePass = storePass;
    }

    /**
     * 设置加解密算法
     *
     * @param algorithm 算法名
     */
    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public MessageDigest getObject() throws Exception {
        return messageDigest;
    }

    public Class<?> getObjectType() {
        return MessageDigest.class;
    }

    public boolean isSingleton() {
        return true;
    }

    public void afterPropertiesSet() throws Exception {
        if (StringUtils.isBlank(jksFile)) {
            throw new IllegalArgumentException("argument 'jksFile' is null.");
        }
        if (StringUtils.isBlank(alias)) {
            throw new IllegalArgumentException("argument 'alias' is null.");
        }
        if (StringUtils.isBlank(storePass)) {
            throw new IllegalArgumentException("argument 'storePass' is null.");
        }
        if (StringUtils.isBlank(algorithm)) {
            throw new IllegalArgumentException("argument 'algorithm' is null.");
        }

        InputStream in = new ClassPathResource(jksFile).getInputStream();

        KeyStore jks = KeyStore.getInstance("JKS");
        jks.load(in, storePass.toCharArray());

        PublicKey publicKey = jks.getCertificate(alias).getPublicKey();
        PrivateKey privateKey = (PrivateKey) jks.getKey(alias, storePass.toCharArray());

        if ("RSA".equals(algorithm)) {
            messageDigest = new RSAMessageDigest(privateKey, publicKey);
        } else {
            throw new IllegalArgumentException("Unknown algorithm. [" + algorithm + "].");
        }
    }
}

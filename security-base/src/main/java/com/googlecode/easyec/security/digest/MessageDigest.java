package com.googlecode.easyec.security.digest;

/**
 * 消息摘要类。
 * <p>此类定义了加解密消息的一般方法。</p>
 *
 * @author JunJie
 */
public interface MessageDigest {

    /**
     * 加密明文消息。
     *
     * @param plainText 明文内容
     * @return 加密后的内容
     * @throws Exception 加密失败抛出相应的异常信息
     */
    String encrypt(String plainText) throws Exception;

    /**
     * 解密密文消息。
     *
     * @param cipherText 加密的消息内容
     * @return 明文内容
     * @throws Exception 解密失败抛出相应的异常信息
     */
    String decrypt(String cipherText) throws Exception;
}

package com.googlecode.easyec.security.rsa;

import com.googlecode.easyec.security.IllegalCipherException;

/**
 * 基于RSA算法的给于客户端使用的业务接口类
 *
 * @author JunJie
 */
public interface RSAClientService {

    /**
     * 使用RSA公钥加密的方法
     *
     * @param data 被加密的数据
     * @return 加密后的数据
     * @throws IllegalCipherException 加密失败异常信息
     */
    byte[] encryptWithPublicKey(byte[] data) throws IllegalCipherException;

    /**
     * 使用RSA公钥解密的方法
     *
     * @param data 已加密的数据
     * @return 解密后的数据
     * @throws IllegalCipherException 解密失败异常信息
     */
    byte[] decryptWithPublicKey(byte[] data) throws IllegalCipherException;
}

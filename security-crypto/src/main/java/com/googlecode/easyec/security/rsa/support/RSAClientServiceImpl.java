package com.googlecode.easyec.security.rsa.support;

import com.googlecode.easyec.security.IllegalCipherException;
import com.googlecode.easyec.security.rsa.RSAClientService;
import org.apache.commons.lang.ArrayUtils;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.util.Assert;

import java.security.interfaces.RSAPublicKey;

/**
 * 基于RSA算法的给于客户端使用的业务实现类
 *
 * @author JunJie
 */
class RSAClientServiceImpl implements RSAClientService {

    private RSAPublicKey publicKey;

    public RSAClientServiceImpl(RSAPublicKey publicKey) {
        Assert.notNull(publicKey, "RSAPublicKey is null.");
        this.publicKey = publicKey;
    }

    @Override
    public byte[] encryptWithPublicKey(byte[] data) throws IllegalCipherException {
        return doEncrypt(
            new RSAKeyParameters(
                false,
                publicKey.getModulus(),
                publicKey.getPublicExponent()
            ), data
        );
    }

    @Override
    public byte[] decryptWithPublicKey(byte[] data) throws IllegalCipherException {
        return doDecrypt(
            new RSAKeyParameters(
                false,
                publicKey.getModulus(),
                publicKey.getPublicExponent()
            ), data
        );
    }

    /**
     * 执行加密的方法
     *
     * @param params <code>RSAKeyParameters</code>
     * @param data   明文数据
     * @return 密文数据
     * @throws IllegalCipherException 加密失败异常信息
     */
    protected byte[] doEncrypt(RSAKeyParameters params, byte[] data) throws IllegalCipherException {
        _checkData(data);

        PKCS1Encoding pkcs1Encoding = new PKCS1Encoding(new RSAEngine());
        pkcs1Encoding.init(true, params);

        try {
            return Base64.encode(
                pkcs1Encoding.processBlock(data, 0, data.length)
            );
        } catch (InvalidCipherTextException e) {
            throw new IllegalCipherException(e);
        }
    }

    /**
     * 执行解密的方法
     *
     * @param params <code>RSAKeyParameters</code>
     * @param data   密文数据
     * @return 明文数据
     * @throws IllegalCipherException 解密失败异常信息
     */
    protected byte[] doDecrypt(RSAKeyParameters params, byte[] data) throws IllegalCipherException {
        _checkData(data);

        PKCS1Encoding pkcs1Encoding = new PKCS1Encoding(new RSAEngine());
        pkcs1Encoding.init(false, params);

        try {
            byte[] bs = Base64.decode(data);
            return pkcs1Encoding.processBlock(bs, 0, bs.length);
        } catch (InvalidCipherTextException e) {
            throw new IllegalCipherException(e);
        }
    }

    /**
     * 返回当前设置的公钥信息
     *
     * @return RSA公钥对象
     */
    protected RSAPublicKey getPublicKey() {
        return publicKey;
    }

    private void _checkData(byte[] data) throws IllegalCipherException {
        if (ArrayUtils.isEmpty(data)) {
            throw new IllegalCipherException("Illegal data info.");
        }
    }
}

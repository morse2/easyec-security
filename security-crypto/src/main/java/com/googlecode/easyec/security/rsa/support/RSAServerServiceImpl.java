package com.googlecode.easyec.security.rsa.support;

import com.googlecode.easyec.security.IllegalCipherException;
import com.googlecode.easyec.security.rsa.RSAServerService;
import org.bouncycastle.crypto.params.RSAKeyParameters;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * 基于RSA算法的给于服务端使用的业务实现类
 *
 * @author JunJie
 */
public class RSAServerServiceImpl extends RSAClientServiceImpl implements RSAServerService {

    private RSAPrivateKey privateKey;

    RSAServerServiceImpl(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
        super(publicKey);
        this.privateKey = privateKey;
    }

    @Override
    public byte[] encryptWithPrivateKey(byte[] data) throws IllegalCipherException {
        return doEncrypt(
            new RSAKeyParameters(
                true,
                privateKey.getModulus(),
                privateKey.getPrivateExponent()
            ), data
        );
    }

    @Override
    public byte[] decryptWithPrivateKey(byte[] data) throws IllegalCipherException {
        return doDecrypt(
            new RSAKeyParameters(
                true,
                privateKey.getModulus(),
                privateKey.getPrivateExponent()
            ), data
        );
    }
}

package com.googlecode.easyec.security.rsa.support;

import com.googlecode.easyec.security.rsa.RSAServerService;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * 基于RSA算法的服务端实现的委托代理工厂类
 *
 * @author JunJie
 */
public class RSAServerServiceFactoryBean implements FactoryBean<RSAServerService>, InitializingBean {

    private RSAServerService serverService;
    private KeyPair keyPair;

    /**
     * 设置秘钥键值对
     *
     * @param keyPair <code>KeyPair</code>
     */
    public void setKeyPair(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    @Override
    public RSAServerService getObject() throws Exception {
        return serverService;
    }

    @Override
    public Class<?> getObjectType() {
        return RSAServerService.class;
    }

    @Override
    public boolean isSingleton() {
        return true;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(keyPair, "KeyPair cannot be null.");
        Assert.isInstanceOf(RSAPublicKey.class, keyPair.getPublic(), "PublicKey must be instance of RSAPublicKey");
        Assert.isInstanceOf(RSAPrivateKey.class, keyPair.getPrivate(), "PrivateKey must be instance of RSAPrivateKey");

        serverService = new RSAServerServiceImpl(
            ((RSAPublicKey) keyPair.getPublic()),
            (RSAPrivateKey) keyPair.getPrivate()
        );
    }
}

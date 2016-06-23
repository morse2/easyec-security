package com.googlecode.easyec.security.rsa.support;

import com.googlecode.easyec.security.rsa.RSAClientService;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;

import java.security.interfaces.RSAPublicKey;

/**
 * 基于RSA算法的客户端实现的委托代理工厂类
 *
 * @author JunJie
 */
public class RSAClientServiceFactoryBean implements FactoryBean<RSAClientService>, InitializingBean {

    private RSAClientService clientService;
    private RSAPublicKey publicKey;

    /**
     * 设置公钥对象
     *
     * @param publicKey <code>RSAPublicKey</code>
     */
    public void setPublicKey(RSAPublicKey publicKey) {
        this.publicKey = publicKey;
    }

    @Override
    public RSAClientService getObject() throws Exception {
        return clientService;
    }

    @Override
    public Class<?> getObjectType() {
        return RSAClientService.class;
    }

    @Override
    public boolean isSingleton() {
        return true;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(publicKey, "RSAPublicKey cannot be null.");

        clientService = new RSAClientServiceImpl(publicKey);
    }
}

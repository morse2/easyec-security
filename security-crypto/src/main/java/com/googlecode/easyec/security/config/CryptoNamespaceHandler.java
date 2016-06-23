package com.googlecode.easyec.security.config;

import org.springframework.beans.factory.xml.NamespaceHandlerSupport;

/**
 * 加解密算法的命名空间的处理类
 *
 * @author JunJie
 */
public class CryptoNamespaceHandler extends NamespaceHandlerSupport {

    @Override
    public void init() {
        registerBeanDefinitionParser("rsa-client", new RSAClientBeanDefinitionParser());
        registerBeanDefinitionParser("rsa-server", new RSAServerBeanDefinitionParser());
    }
}

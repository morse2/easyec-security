package com.googlecode.easyec.security.config;

import com.googlecode.easyec.security.rsa.support.RSAServerServiceFactoryBean;
import com.googlecode.easyec.security.utils.PemUtils;
import org.apache.commons.lang3.BooleanUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.parsing.BeanDefinitionParsingException;
import org.springframework.beans.factory.parsing.Location;
import org.springframework.beans.factory.parsing.Problem;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.AbstractSingleBeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.beans.factory.xml.XmlReaderContext;
import org.springframework.core.io.Resource;
import org.w3c.dom.Element;

import java.io.InputStream;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * RSA算法客户端Bean定义的解析类
 *
 * @author JunJie
 */
class RSAServerBeanDefinitionParser extends AbstractSingleBeanDefinitionParser {

    @Override
    protected Class<?> getBeanClass(Element element) {
        return RSAServerServiceFactoryBean.class;
    }

    @Override
    protected void doParse(Element element, ParserContext ctx, BeanDefinitionBuilder builder) {
        String publicKeyPath = element.getAttribute("private-key-path");
        String usePassword = element.getAttribute("use-password");
        String passwordKey = element.getAttribute("password-key");
        String charset = element.getAttribute("charset");

        XmlReaderContext readerContext = ctx.getReaderContext();
        Resource resource = readerContext.getResourceLoader().getResource(publicKeyPath);

        try {
            char[] pass = null;
            if (BooleanUtils.toBoolean(usePassword)) {
                String val = System.getProperty(passwordKey);
                if (StringUtils.isNotBlank(val)) {
                    pass = val.toCharArray();
                }
            }

            InputStream in = resource.getInputStream();
            Object o = PemUtils.read(in, pass, charset);
            if (!PemUtils.isKeyPair(o)) {
                throw new IllegalArgumentException("There isn't a private key file.");
            }

            KeyPair keyPair = (KeyPair) o;
            if (!(keyPair.getPublic() instanceof RSAPublicKey)) {
                throw new IllegalArgumentException("There isn't a RSAPublicKey object.");
            }

            if (!(keyPair.getPrivate() instanceof RSAPrivateKey)) {
                throw new IllegalArgumentException("There isn't a RSAPrivateKey object.");
            }

            builder.addPropertyValue("keyPair", keyPair);
        } catch (Exception e) {
            throw new BeanDefinitionParsingException(
                new Problem(e.getMessage(), new Location(readerContext.getResource()))
            );
        }
    }
}

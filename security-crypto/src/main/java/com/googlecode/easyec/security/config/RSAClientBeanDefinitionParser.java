package com.googlecode.easyec.security.config;

import com.googlecode.easyec.security.rsa.support.RSAClientServiceFactoryBean;
import com.googlecode.easyec.security.utils.PemUtils;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
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
import java.security.interfaces.RSAPublicKey;

/**
 * RSA算法客户端Bean定义的解析类
 *
 * @author JunJie
 */
class RSAClientBeanDefinitionParser extends AbstractSingleBeanDefinitionParser {

    @Override
    protected Class<?> getBeanClass(Element element) {
        return RSAClientServiceFactoryBean.class;
    }

    @Override
    protected void doParse(Element element, ParserContext ctx, BeanDefinitionBuilder builder) {
        String publicKeyPath = element.getAttribute("public-key-path");
        String charset = element.getAttribute("charset");

        XmlReaderContext readerContext = ctx.getReaderContext();
        Resource resource = readerContext.getResourceLoader().getResource(publicKeyPath);

        try {
            InputStream in = resource.getInputStream();
            Object o = new JcaPEMKeyConverter().getPublicKey(
                ((SubjectPublicKeyInfo) PemUtils.read(in, charset))
            );

            if (!PemUtils.isPublicKey(o)) {
                throw new IllegalArgumentException("There isn't a public key file.");
            }

            if (!(o instanceof RSAPublicKey)) {
                throw new IllegalArgumentException("There isn't a RSAPublicKey object.");
            }

            builder.addPropertyValue("publicKey", o);
        } catch (Exception e) {
            throw new BeanDefinitionParsingException(
                new Problem(e.getMessage(), new Location(readerContext.getResource()))
            );
        }
    }
}

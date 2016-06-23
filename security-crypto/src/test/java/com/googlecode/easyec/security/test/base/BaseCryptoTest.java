package com.googlecode.easyec.security.test.base;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.AbstractJUnit4SpringContextTests;

import static java.security.Security.addProvider;
import static java.security.Security.getProvider;

/**
 * Created by JunJie on 6/17/16.
 */
@ContextConfiguration(locations = "classpath:spring/test/applicationContext-*.xml")
public class BaseCryptoTest extends AbstractJUnit4SpringContextTests {

    static {
        if (getProvider("BC") == null) addProvider(new BouncyCastleProvider());
    }
}

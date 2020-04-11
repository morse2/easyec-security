package com.googlecode.easyec.security.test.jjwt;

import com.googlecode.easyec.security.support.TokenOperator;
import io.jsonwebtoken.Claims;
import org.junit.Assert;
import org.junit.Test;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.AbstractJUnit4SpringContextTests;

import javax.annotation.Resource;
import java.util.HashMap;
import java.util.Map;

@ContextConfiguration(locations = "classpath:spring/test/applicationContext-jjwt.xml")
public class TokenTestCase extends AbstractJUnit4SpringContextTests {

    @Resource
    private TokenOperator rsaTokenOperator;
    @Resource
    private TokenOperator hmacShaTokenOperator;

    @Test
    public void jwtWithRsa() {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", "admin");

        String jwt = rsaTokenOperator.encode(claims);
        Assert.assertNotNull(jwt);
        Claims parsedClaims = rsaTokenOperator.decode(jwt);
        Assert.assertNotNull(parsedClaims);
        String userId = (String) parsedClaims.get("userId");
        Assert.assertEquals(claims.get("userId"), userId);
    }

    @Test
    public void jwtWithHmacSha() {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", "admin");

        String jwt = hmacShaTokenOperator.encode(claims);
        Assert.assertNotNull(jwt);
        Claims parsedClaims = hmacShaTokenOperator.decode(jwt);
        Assert.assertNotNull(parsedClaims);
        String userId = (String) parsedClaims.get("userId");
        Assert.assertEquals(claims.get("userId"), userId);
    }
}

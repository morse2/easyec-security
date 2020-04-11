package com.googlecode.easyec.security.support.internal;

import com.googlecode.easyec.security.support.TokenOperator;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;

import java.security.Key;

public class HmacShaTokenOperator implements TokenOperator, InitializingBean {

    private String secret;

    public HmacShaTokenOperator(String secret) {
        this.secret = secret;
    }

    public String getSecret() {
        return secret;
    }

    @Override
    public String encode(Claims claims) {
        return Jwts.builder()
            .setClaims(claims)
            .signWith(getSecretKey())
            .compact();
    }

    @Override
    public Claims decode(String token) {
        return Jwts.parserBuilder()
            .setSigningKey(getSecretKey())
            .build()
            .parseClaimsJws(token)
            .getBody();
    }

    protected Key getSecretKey() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(getSecret()));
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(secret, "Secret is null.");
    }
}

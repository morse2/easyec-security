package com.googlecode.easyec.security.support;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.impl.DefaultClaims;

import java.util.Map;

public interface TokenOperator {

    default String encode(Map<String, Object> claims) {
        return encode(new DefaultClaims(claims));
    }

    String encode(Claims claims);

    Claims decode(String token);
}

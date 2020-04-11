package com.googlecode.easyec.security;

import org.springframework.security.core.AuthenticationException;

/**
 * 表示令牌值已经过期的异常类
 *
 * @author JunJie.Z
 */
public class TokenExpiredException extends AuthenticationException {

    private static final long serialVersionUID = 4979703102795266383L;

    public TokenExpiredException(String msg, Throwable t) {
        super(msg, t);
    }

    public TokenExpiredException(String msg) {
        super(msg);
    }
}

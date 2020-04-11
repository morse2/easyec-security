package com.googlecode.easyec.security;

import org.springframework.security.core.AuthenticationException;

/**
 * 表示token无效的异常类
 *
 * @author JunJie.Z
 */
public class InvalidTokenException extends AuthenticationException {

    private static final long serialVersionUID = 3473827156817774624L;

    public InvalidTokenException(String msg, Throwable t) {
        super(msg, t);
    }

    public InvalidTokenException(String msg) {
        super(msg);
    }
}

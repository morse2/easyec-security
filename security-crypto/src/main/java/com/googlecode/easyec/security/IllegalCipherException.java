package com.googlecode.easyec.security;

/**
 * 表示无效的加解密的异常类
 *
 * @author JunJie
 */
public class IllegalCipherException extends Exception {

    private static final long serialVersionUID = -8374495245083973437L;

    public IllegalCipherException(String message) {
        super(message);
    }

    public IllegalCipherException(String message, Throwable cause) {
        super(message, cause);
    }

    public IllegalCipherException(Throwable cause) {
        super(cause);
    }
}

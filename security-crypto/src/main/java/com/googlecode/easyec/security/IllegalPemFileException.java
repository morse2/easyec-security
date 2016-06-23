package com.googlecode.easyec.security;

/**
 * 表示PEM文件格式不合法的异常类
 *
 * @author JunJie
 */
public class IllegalPemFileException extends Exception {

    private static final long serialVersionUID = -5927009636833035840L;

    public IllegalPemFileException(String message) {
        super(message);
    }

    public IllegalPemFileException(Throwable cause) {
        super(cause);
    }

    public IllegalPemFileException(String message, Throwable cause) {
        super(message, cause);
    }
}

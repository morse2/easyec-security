package com.googlecode.easyec.security.handler;

import com.googlecode.easyec.security.InvalidTokenException;
import com.googlecode.easyec.security.TokenExpiredException;
import org.springframework.security.authentication.*;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedCredentialsNotFoundException;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationException;

public class DefaultAuthenticationFailureHandler extends AbstractAuthenticationFailureHandler {

    protected int handleError(AuthenticationException ex) {
        if (ex instanceof BadCredentialsException) {
            return 10001;  // 用户名或密码不正确
        }
        if (ex instanceof UsernameNotFoundException) {
            return 10002;  // 用户不存在
        }
        if (ex instanceof AccountExpiredException) {
            return 10003;  // 账号已过期
        }
        if (ex instanceof CredentialsExpiredException) {
            return 10004;  // 凭据已过期
        }
        if (ex instanceof DisabledException) {
            return 10005;  // 账号已禁用
        }
        if (ex instanceof LockedException) {
            return 10006;  // 账号已被锁
        }
        if (ex instanceof AuthenticationCredentialsNotFoundException) {
            return 10007;  // 无效认证的凭据信息
        }
        if (ex instanceof AuthenticationServiceException) {
            return 10010;  // 认证服务异常
        }
        if (ex instanceof RememberMeAuthenticationException) {
            return 10011;  // 记住我认证失败
        }
        if (ex instanceof PreAuthenticatedCredentialsNotFoundException) {
            return 10012;  // 无效的预认证的凭证信息
        }
        if (ex instanceof InsufficientAuthenticationException) {
            return 10013;  // 访问的资源需要提供有效用户凭证
        }
        if (ex instanceof InvalidTokenException) {
            return 10014;  // 客户端提供的令牌值已经失效
        }
        if (ex instanceof TokenExpiredException) {
            return 10015; // 客户端提供的令牌值已经过期
        }

        // 统一的认证失败的错误代码
        return 10099;
    }
}

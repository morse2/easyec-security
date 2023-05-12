package com.googlecode.easyec.security.service;

import org.springframework.security.core.userdetails.UserDetails;

import javax.servlet.http.HttpServletRequest;

/**
 * 用户令牌业务接口类
 *
 * @param <T> <code>UserDetails</code>
 * @author junjie
 */
public interface UserTokenService<T extends UserDetails> {

    /**
     * 为用户创建一个新的令牌
     *
     * @param user 用户对象
     * @return 令牌值
     */
    String createNew(T user);

    /**
     * 通过令牌获取用户对象信息，
     * 该方法默认验证用户状态
     *
     * @param token 令牌值
     * @return 用户对象
     */
    T getUser(String token);

    /**
     * 通过令牌获取用户对象信息，
     * 并指出是否要验证用户的状态。
     *
     * @param token    令牌值
     * @param validate 验证用户状态
     * @return 用户对象
     */
    T getUser(String token, boolean validate);

    /**
     * 通过<code>HttpServletRequest</code>
     * 获取用户对象信息
     *
     * @param request HTTP请求对象
     * @return 用户对象
     */
    T getUser(HttpServletRequest request);

    /**
     * 通过<code>HttpServletRequest</code>
     * 获取用户对象信息
     *
     * @param request  HTTP请求对象
     * @param validate 验证用户状态
     * @return 用户对象
     */
    T getUser(HttpServletRequest request, boolean validate);

    /**
     * 移除给定的用户信息
     *
     * @param user 用户对象
     */
    void remove(T user);

    /**
     * 刷新用户的令牌过期时间，
     * 该方法会强制刷新令牌的过期时间，
     * 并返回一个新的令牌值。
     *
     * @param user 用户对象
     * @return 令牌值
     */
    String refresh(T user);

    /**
     * 计算并返回登录用户的令牌过期时间，
     * 精确到秒。
     *
     * @return 超时时间(秒)
     */
    int getExpireIn();
}

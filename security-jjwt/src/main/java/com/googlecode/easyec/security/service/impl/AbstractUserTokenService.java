package com.googlecode.easyec.security.service.impl;

import com.googlecode.easyec.security.InvalidTokenException;
import com.googlecode.easyec.security.TokenExpiredException;
import com.googlecode.easyec.security.service.UserTokenService;
import com.googlecode.easyec.security.support.TokenOperator;
import com.googlecode.easyec.security.userdetails.EcUser;
import io.jsonwebtoken.Claims;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.DateFormatUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

import static java.lang.System.currentTimeMillis;
import static org.apache.commons.lang3.StringUtils.isBlank;
import static org.apache.commons.lang3.StringUtils.isNotBlank;

public abstract class AbstractUserTokenService<T extends EcUser> implements UserTokenService<T>, InitializingBean {

    protected final Logger logger = LoggerFactory.getLogger(getClass());
    private int expireTime = 30 * 60;
    private String header = "Authorization";
    private TokenOperator tokenOperator;

    public void setHeader(String header) {
        this.header = header;
    }

    public void setExpireTime(int expireTime) {
        this.expireTime = expireTime;
    }

    public String getHeader() {
        return header;
    }

    public int getExpireTime() {
        return expireTime;
    }

    public TokenOperator getTokenOperator() {
        return tokenOperator;
    }

    public void setTokenOperator(TokenOperator tokenOperator) {
        this.tokenOperator = tokenOperator;
    }

    @Override
    public String createNew(T user) {
        return refresh(user, false);
    }

    @Override
    public T getUser(String token) {
        return getUser(token, true);
    }

    @Override
    public T getUser(String token, boolean validate) {
        if (isBlank(token)) return null;

        Claims claims;

        try {
            if (logger.isDebugEnabled()) {
                logger.debug("Token [{}] will being process.", token);
            }

            claims = getTokenOperator().decode(token);
            if (logger.isDebugEnabled()) {
                logger.debug("Token [{}] has been decoded successfully. Claims: [{}].",
                    token, claims);
            }
        } catch (Exception e) {
            logger.error("Token [{}] cannot be decoded successfully.", token);
            throw new InvalidTokenException(e.getMessage(), e);
        }

        String userId = (String) claims.get("userId");
        if (logger.isDebugEnabled()) {
            logger.debug("User id from token [{}] is: [{}].", token, userId);
        }

        T user = doGetUser(userId);
        if (logger.isDebugEnabled()) {
            logger.debug("Does user object find by user id [{}] ? [{}]", userId, (user != null));
        }

        if (user != null) {
            // 校验客户端的token与当前用户缓存的token是否一致，从而保持一个用户同时只能在一个客户端登录
            String tokenFromCache = (String) user.getAttribute("jwtToken");
            if (logger.isDebugEnabled()) {
                logger.debug("User [{}]'s token from cache is: [{}].", userId, tokenFromCache);
            }

            if (!StringUtils.equals(token, tokenFromCache)) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Token doesn't match. Expected: [{}], actual: [{}].", token, tokenFromCache);
                }

                throw new InvalidTokenException("Token is invalid from client. [" + token + "]");
            }

            if (validate) {
                validateUser(user);
                logger.debug("User [{}]'s token [{}] is valid.", userId, token);
            }
        }

        return user;
    }

    @Override
    public T getUser(HttpServletRequest request) {
        String token = request.getHeader(getHeader());
        return isBlank(token) ? null : getUser(token);
    }

    @Override
    public void remove(T user) {
        if (user != null) doRemoveUser(getUserId(user));
    }

    @Override
    public String refresh(T user) {
        return refresh(user, true);
    }

    @Override
    public int getExpireIn() {
        return expireTime;
    }

    protected String refresh(T user, boolean force) {
        if (logger.isDebugEnabled()) {
            logger.debug("Prepare to refresh user's token. User: [{}]." +
                " Is this operation force? [{}]", user.getUsername(), force);
        }

        String userId = getUserId(user);
        if (logger.isDebugEnabled()) {
            logger.debug("User id with username is: [{}], [{}].", userId, user.getUsername());
        }

        if (!force) {
            boolean isUserInCache = false;
            String token = (String) user.getAttribute("jwtToken");
            if (logger.isDebugEnabled()) {
                logger.debug("Token from user, [{}]: [{}].", user.getUsername(), token);
            }

            // 如果当前user对象中无token数据，则试图从缓存中获取user数据
            if (isBlank(token)) {
                T userInCache = doGetUser(userId);
                if (logger.isDebugEnabled()) {
                    logger.debug("Is user [{}] in cache? [{}]", userId, (userInCache != null));
                }

                if (userInCache != null) {
                    token = (String) userInCache.getAttribute("jwtToken");
                    isUserInCache = true;
                }
            }

            if (isNotBlank(token)) {
                try {
                    validateUser(user);

                    if (logger.isDebugEnabled()) {
                        logger.debug("User [{}]'s is valid, it can be reused.", user.getUsername());
                    }

                    if (isUserInCache) {
                        user.addAttribute("jwtToken", token);
                        updateLoginInfo(user);
                        doSaveUser(user);
                    }

                    return token;
                } catch (TokenExpiredException e) {
                    if (logger.isDebugEnabled()) {
                        logger.debug("User [{}]'s token is expired, so it will be reset.",
                            user.getUsername());
                    }

                    // if token is expired, then clear this token
                    user.removeAttribute("jwtToken");
                    user.removeAttribute("loginTime");
                }
            }
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Do generate user [{}]'s new token.", user.getUsername());
        }

        updateLoginInfo(user);

        if (logger.isDebugEnabled()) {
            logger.debug("User [{}]'s id which will be set into cache is: [{}].",
                user.getUsername(), userId);
        }

        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userId);
        claims.put("expireAt", user.getAttribute("expireAt"));
        String token = getTokenOperator().encode(claims);

        user.addAttribute("jwtToken", token);
        // do save user
        doSaveUser(user);

        if (logger.isDebugEnabled()) {
            logger.debug("User [{}]'s new token has been generated. Token value: [{}].",
                user.getUsername(), token
            );
        }

        return token;
    }

    protected String getUserId(T user) {
        return user.getUsername();
    }

    protected boolean isExpired(T user) {
        Long expireAt = (Long) user.getAttribute("expireAt");
        return expireAt == null || (expireAt - currentTimeMillis()) < 5 * 60 * 1000;
    }

    /**
     * 验证用户状态的方法
     *
     * @param user 用户对象
     */
    protected void validateUser(T user) {
        // 判断令牌值是否过期
        if (isExpired(user)) {
            throw new TokenExpiredException("Token is expired. ["
                + user.getAttribute("jwtToken") + "]");
        }
    }

    private void updateLoginInfo(T user) {
        if (user.getAttribute("loginTime") == null) {
            long loginAt = currentTimeMillis();
            if (logger.isDebugEnabled()) {
                logger.debug("User [{}]'s login time: [{}].", user.getUsername(),
                    DateFormatUtils.format(loginAt, "yyyy-MM-dd HH:mm:ss"));
            }

            user.addAttribute("loginTime", loginAt);
        }

        long expireAt = currentTimeMillis() + expireTime * 1000L;
        if (logger.isDebugEnabled()) {
            logger.debug("User [{}]'s token will be expired at: [{}].", user.getUsername(),
                DateFormatUtils.format(expireAt, "yyyy-MM-dd HH:mm:ss"));
        }

        user.addAttribute("expireAt", expireAt);
    }

    /**
     * 执行保存当前登录用户的方法
     *
     * @param user 用户对象
     */
    abstract protected void doSaveUser(T user);

    /**
     * 执行查询用户的方法
     *
     * @param userId 用户ID
     * @return 用户对象
     */
    abstract protected T doGetUser(String userId);

    /**
     * 执行删除用户的方法
     *
     * @param userId 用户ID
     */
    abstract protected void doRemoveUser(String userId);

    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(header, "JWT header is null.");
        Assert.notNull(tokenOperator, "TokenOperator is null.");
        Assert.isTrue(expireTime > 0, "Expire time must be greater than 0.");
    }
}

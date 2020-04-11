package com.googlecode.easyec.security.service.impl;

import com.googlecode.easyec.security.userdetails.EcUser;
import org.springframework.security.core.userdetails.UserCache;
import org.springframework.util.Assert;

public class CachingUserTokenService<T extends EcUser> extends AbstractUserTokenService<T> {

    private UserCache userCache;

    public UserCache getUserCache() {
        return userCache;
    }

    public void setUserCache(UserCache userCache) {
        this.userCache = userCache;
    }

    @Override
    protected void doSaveUser(T user) {
        getUserCache().putUserInCache(user);
    }

    @Override
    @SuppressWarnings("unchecked")
    protected T doGetUser(String userId) {
        return (T) getUserCache().getUserFromCache(userId);
    }

    @Override
    protected void doRemoveUser(String userId) {
        getUserCache().removeUserFromCache(userId);
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        super.afterPropertiesSet();
        Assert.notNull(userCache, "Bean 'UserCache' mustn't be null.");
    }
}

package com.googlecode.easyec.security.userdetails.cache;

import com.googlecode.easyec.caching.CacheService;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.SmartFactoryBean;
import org.springframework.security.core.userdetails.UserCache;
import org.springframework.util.Assert;

public class EcUserCacheFactoryBean implements SmartFactoryBean<UserCache>, InitializingBean {

    private CacheService cacheService;
    private String cacheName;

    public String getCacheName() {
        return cacheName;
    }

    public void setCacheName(String cacheName) {
        this.cacheName = cacheName;
    }

    public CacheService getCacheService() {
        return cacheService;
    }

    public void setCacheService(CacheService cacheService) {
        this.cacheService = cacheService;
    }

    @Override
    public UserCache getObject() throws Exception {
        return new EcUserCache(getCacheName(), getCacheService());
    }

    @Override
    public Class<?> getObjectType() {
        return UserCache.class;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(cacheName, "Cache name cannot be null.");
    }
}

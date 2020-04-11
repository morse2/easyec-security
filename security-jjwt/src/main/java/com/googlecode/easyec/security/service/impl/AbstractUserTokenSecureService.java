package com.googlecode.easyec.security.service.impl;

import com.googlecode.easyec.security.service.UserTokenSecureService;
import com.googlecode.easyec.security.service.UserTokenService;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.util.Assert;

public abstract class AbstractUserTokenSecureService implements UserTokenSecureService, InitializingBean {

    private UserTokenService<UserDetails> userTokenService;

    public UserTokenService<UserDetails> getUserTokenService() {
        return userTokenService;
    }

    public void setUserTokenService(UserTokenService<UserDetails> userTokenService) {
        this.userTokenService = userTokenService;
    }

    @Override
    public UserDetails loadUserDetails(PreAuthenticatedAuthenticationToken token) throws UsernameNotFoundException {
        UserDetails user = getUserTokenService().getUser((String) token.getPrincipal());
        if (user == null) {
            throw new UsernameNotFoundException("Cannot find user by token. [" + token.getPrincipal() + "]");
        }

        return user;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(userTokenService, "Bean 'UserTokenService' cannot be null.");
    }
}

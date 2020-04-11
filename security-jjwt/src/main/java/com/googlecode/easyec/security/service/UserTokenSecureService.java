package com.googlecode.easyec.security.service;

import com.googlecode.easyec.security.userdetails.UserDetailsServiceX;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

public interface UserTokenSecureService extends UserDetailsServiceX, AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> {

    @Override
    UserDetails loadUserDetails(PreAuthenticatedAuthenticationToken token) throws UsernameNotFoundException;

    @Override
    UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
}

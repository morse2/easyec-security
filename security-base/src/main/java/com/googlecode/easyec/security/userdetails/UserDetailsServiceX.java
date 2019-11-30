package com.googlecode.easyec.security.userdetails;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;

import static org.apache.commons.collections4.CollectionUtils.isNotEmpty;

public interface UserDetailsServiceX extends UserDetailsService {

    default boolean hasGrantedRoles(Authentication authentication) {
        return authentication != null && isNotEmpty(authentication.getAuthorities());
    }
}

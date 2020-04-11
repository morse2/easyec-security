package com.googlecode.easyec.security.handler;

import org.springframework.security.core.userdetails.UserDetails;

import java.util.HashMap;
import java.util.Map;

public class DefaultLogoutSuccessHandler extends AbstractLogoutSuccessHandler {

    @Override
    protected Object createMessageObject(UserDetails user) {
        Map<String, Object> result = new HashMap<>();
        result.put("errorcode", 0);
        return result;
    }
}

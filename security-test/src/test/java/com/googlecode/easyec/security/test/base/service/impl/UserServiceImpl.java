package com.googlecode.easyec.security.test.base.service.impl;

import com.googlecode.easyec.security.test.base.service.UserService;
import org.springframework.security.access.prepost.PreAuthorize;

public class UserServiceImpl implements UserService {

    @Override
    @PreAuthorize("hasRole('ADMIN')")
    public String sayHello() {
        return "Hello world.";
    }
}

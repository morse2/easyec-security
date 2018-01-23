package com.googlecode.easyec.security.test.base;

import com.googlecode.easyec.security.test.base.service.UserService;
import com.googlecode.easyec.security.test.base.service.impl.UserServiceImpl;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;

import javax.annotation.Resource;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration
@WebAppConfiguration
public class MethodSecurityTest {

    @Resource
    private UserService userService;

    @Test(expected = AuthenticationCredentialsNotFoundException.class)
    public void sayHello() {
        userService.sayHello();
    }

    @Test(expected = AccessDeniedException.class)
    @WithMockUser
    public void sayHelloWithUser() {
        userService.sayHello();
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    public void sayHelloWithAdmin() {
        userService.sayHello();
    }

    @Configuration
    @EnableWebSecurity
    @EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
    static class Config {

        @Bean
        public UserService userService() {
            return new UserServiceImpl();
        }
    }
}

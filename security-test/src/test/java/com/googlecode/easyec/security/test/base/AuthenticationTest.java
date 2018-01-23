package com.googlecode.easyec.security.test.base;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import javax.servlet.Filter;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration
@WebAppConfiguration
public class AuthenticationTest {

    @Autowired
    private WebApplicationContext context;

    @Autowired
    private Filter springSecurityFilterChain;

    private MockMvc mvc;

    @Before
    public void setup() {
        mvc = MockMvcBuilders
            .webAppContextSetup(context)
            .addFilters(springSecurityFilterChain)
            .build();
    }

    @Test
    public void requiresAuthentication() throws Exception {
        mvc
            .perform(get("/"))
            .andExpect(status().isFound())
            .andExpect(status().isForbidden());
    }

    @Test
    public void authenticationSuccess() throws Exception {
        mvc
            .perform(formLogin().user("admin").password("Password01"))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/"))
            .andExpect(authenticated().withUsername("admin").withRoles("ADMIN"));
    }

    @Test
    public void authenticationFailed() throws Exception {
        mvc
            .perform(formLogin().user("admin").password("invalid"))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/login?error"))
            .andExpect(unauthenticated());
    }

    @Configuration
    @EnableWebMvc
    @EnableWebSecurity
    static class Config extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth.inMemoryAuthentication()
                .withUser("admin")
                .password("Password01")
                .roles("ADMIN");
        }
    }
}

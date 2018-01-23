package com.googlecode.easyec.security.test.base.initializer;

import com.googlecode.easyec.security.test.base.config.WebSecurityConfig;
import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;

public class WebSecurityAppInitializer extends AbstractSecurityWebApplicationInitializer {

    public WebSecurityAppInitializer() {
        super(WebSecurityConfig.class);
    }
}

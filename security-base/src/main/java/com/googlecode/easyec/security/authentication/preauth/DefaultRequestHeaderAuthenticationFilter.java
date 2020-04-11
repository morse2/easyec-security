package com.googlecode.easyec.security.authentication.preauth;

import org.springframework.security.web.authentication.preauth.RequestHeaderAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;

public class DefaultRequestHeaderAuthenticationFilter extends RequestHeaderAuthenticationFilter {

    private boolean continueThrowException;

    public DefaultRequestHeaderAuthenticationFilter() {
        setContinueFilterChainOnUnsuccessfulAuthentication(false);
    }

    public boolean isContinueThrowException() {
        return continueThrowException;
    }

    public void setContinueThrowException(boolean continueThrowException) {
        this.continueThrowException = continueThrowException;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        try {
            super.doFilter(request, response, chain);
        } catch (Exception e) {
            if (isContinueThrowException()) {
                throw e;
            }
        }
    }
}

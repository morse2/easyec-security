package com.googlecode.easyec.security.handler;

import com.googlecode.easyec.security.support.AbstractHttpMessageHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.http.MediaType.APPLICATION_JSON_UTF8;

public abstract class AbstractAuthenticationFailureHandler extends AbstractHttpMessageHandler
    implements AuthenticationFailureHandler, AuthenticationEntryPoint, InitializingBean {

    protected final Logger logger = LoggerFactory.getLogger(getClass());

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException ex) throws IOException, ServletException {
        writeMessage(getFailureMessage(ex), APPLICATION_JSON_UTF8, response);
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException ex) throws IOException, ServletException {
        onAuthenticationFailure(request, response, ex);
    }

    protected Object getFailureMessage(AuthenticationException e) {
        logger.error(e.getMessage(), e);
        Map<String, Object> result = new HashMap<>();
        result.put("result_code", handleError(e));
        return result;
    }

    /**
     * 处理认证异常并返回对应的错误码
     *
     * @param ex <code>AuthenticationException</code>
     * @return 错误码
     */
    abstract protected int handleError(AuthenticationException ex);
}

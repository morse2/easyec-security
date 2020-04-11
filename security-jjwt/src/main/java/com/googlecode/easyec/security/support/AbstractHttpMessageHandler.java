package com.googlecode.easyec.security.support;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public abstract class AbstractHttpMessageHandler implements InitializingBean {

    private HttpMessageConverter<Object> httpMessageConverter;

    public HttpMessageConverter<Object> getHttpMessageConverter() {
        return httpMessageConverter;
    }

    public void setHttpMessageConverter(HttpMessageConverter<Object> httpMessageConverter) {
        this.httpMessageConverter = httpMessageConverter;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(httpMessageConverter, "Bean 'HttpMessageConverter' cannot null.");
    }

    protected void writeMessage(Object message, MediaType mediaType, HttpServletResponse response) throws IOException {
        getHttpMessageConverter().write(message, mediaType, new ServletServerHttpResponse(response));
    }
}

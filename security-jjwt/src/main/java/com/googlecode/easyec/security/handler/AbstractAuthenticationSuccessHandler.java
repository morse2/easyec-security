package com.googlecode.easyec.security.handler;

import com.googlecode.easyec.security.service.UserTokenService;
import com.googlecode.easyec.security.support.AbstractHttpMessageHandler;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.Assert;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.springframework.http.MediaType.APPLICATION_JSON_UTF8;

public abstract class AbstractAuthenticationSuccessHandler<T extends UserDetails> extends AbstractHttpMessageHandler
    implements AuthenticationSuccessHandler, InitializingBean {

    private UserTokenService<T> userTokenService;

    public UserTokenService<T> getUserTokenService() {
        return userTokenService;
    }

    public void setUserTokenService(UserTokenService<T> userTokenService) {
        this.userTokenService = userTokenService;
    }

    @Override
    @SuppressWarnings("unchecked")
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        T user = (T) authentication.getPrincipal();
        setUserProperties(user);

        String newToken = getUserTokenService().createNew(user);
        writeMessage(createMessageObject(user, newToken), APPLICATION_JSON_UTF8, response);
    }

    /**
     * 为登录用户设置扩展的属性
     *
     * @param user <code>UserDetails</code>对象
     */
    protected void setUserProperties(T user) {}

    /**
     * 创建客户端响应的消息对象
     *
     * @param user     <code>UserDetails</code>对象
     * @param newToken 新token值
     * @return 消息对象
     */
    abstract protected Object createMessageObject(T user, String newToken);

    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(userTokenService, "Bean 'UserTokenService' cannot be null.");
    }
}

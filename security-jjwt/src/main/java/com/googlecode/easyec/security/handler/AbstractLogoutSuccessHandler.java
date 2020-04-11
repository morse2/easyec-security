package com.googlecode.easyec.security.handler;

import com.googlecode.easyec.security.service.UserTokenService;
import com.googlecode.easyec.security.support.AbstractHttpMessageHandler;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.util.Assert;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.springframework.http.MediaType.APPLICATION_JSON_UTF8;

/**
 * 默认JSON格式登出成功的处理类
 */
public abstract class AbstractLogoutSuccessHandler extends AbstractHttpMessageHandler implements LogoutSuccessHandler, InitializingBean {

    private UserTokenService<UserDetails> userTokenService;

    public void setUserTokenService(UserTokenService<UserDetails> userTokenService) {
        this.userTokenService = userTokenService;
    }

    public UserTokenService<UserDetails> getUserTokenService() {
        return userTokenService;
    }

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        UserDetails user = getUserTokenService().getUser(request);
        if (user != null) {
            getUserTokenService().remove(user);
        }

        writeMessage(createMessageObject(user), APPLICATION_JSON_UTF8, response);
    }

    /**
     * 创建登录成功的消息对象
     *
     * @param user <code>UserDetails</code>，该对象在此次调用后，将被销毁
     * @return 消息对象
     */
    abstract protected Object createMessageObject(UserDetails user);

    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(userTokenService, "Bean 'UserTokenService' cannot be null.");
    }
}

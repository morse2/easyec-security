package com.googlecode.easyec.security.utils;

import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.access.WebInvocationPrivilegeEvaluator;
import org.springframework.security.web.context.support.SecurityWebApplicationContextUtils;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

/**
 * @author junjie
 */
public class SecurityUtils {

    private SecurityUtils() {}

    /**
     * 从当前请求或Spring上下文中查找
     * <code>WebInvocationPrivilegeEvaluator</code>
     * 对象实例。如果找不到，则抛出异常信息。
     *
     * @param request <code>HttpServletRequest</code>
     * @return <code>WebInvocationPrivilegeEvaluator</code>
     */
    public static WebInvocationPrivilegeEvaluator getPrivilegeEvaluator(HttpServletRequest request) {
        WebInvocationPrivilegeEvaluator privEvaluatorFromRequest = (WebInvocationPrivilegeEvaluator) request
            .getAttribute(WebAttributes.WEB_INVOCATION_PRIVILEGE_EVALUATOR_ATTRIBUTE);
        if (privEvaluatorFromRequest != null) return privEvaluatorFromRequest;

        ApplicationContext ctx = SecurityWebApplicationContextUtils.findRequiredWebApplicationContext(request.getServletContext());
        Map<String, WebInvocationPrivilegeEvaluator> wipes = ctx.getBeansOfType(WebInvocationPrivilegeEvaluator.class);

        Assert.isTrue(wipes.size() > 0,
            "No visible WebInvocationPrivilegeEvaluator instance could be found in the application context."
        );

        return (WebInvocationPrivilegeEvaluator) wipes.values().toArray()[0];
    }

    /**
     * 判断给定的URI对于当前用户来说，
     * 是否有权限访问。
     *
     * @param request <code>HttpServletRequest</code>
     * @param uri     请求的URI
     * @return 布尔值
     */
    public static boolean isUriAllowed(HttpServletRequest request, String uri) {
        return isUriAllowed(request, uri, null);
    }

    /**
     * 判断给定的URI对于当前用户来说，
     * 是否有权限访问。
     *
     * @param request <code>HttpServletRequest</code>
     * @param uri     请求的URI
     * @param method  请求的方法
     * @return 布尔值
     */
    public static boolean isUriAllowed(HttpServletRequest request, String uri, RequestMethod method) {
        return getPrivilegeEvaluator(request)
            .isAllowed(
                request.getContextPath(),
                uri, method != null ? method.name() : null,
                (Authentication) request.getUserPrincipal()
            );
    }

    /**
     * 从Spring Security上下文对象中获取当前认证对象
     *
     * @return <code>Authentication</code>
     */
    public static Authentication getPrincipal() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

    /**
     * 从<code>HttpServletRequest</code>对象中
     * 获取当前认证对象信息
     *
     * @param request <code>HttpServletRequest</code>
     * @return <code>Authentication</code>
     */
    public static Authentication getPrincipal(HttpServletRequest request) {
        return ((Authentication) request.getUserPrincipal());
    }

    /**
     * 判断当前登录用户是否是匿名（未认证）用户
     *
     * @return 布尔值
     */
    public static boolean isAnonymous() {
        Authentication principal = getPrincipal();
        return principal == null || principal instanceof AnonymousAuthenticationToken;
    }

    /**
     * 获取当前登录用户对象
     *
     * @return Spring <code>User</code>对象
     */
    public static User getUser() {
        return !isAnonymous()
            ? (User) getPrincipal().getPrincipal()
            : null;
    }
}

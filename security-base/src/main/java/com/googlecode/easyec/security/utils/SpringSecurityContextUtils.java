package com.googlecode.easyec.security.utils;

import com.googlecode.easyec.security.userdetails.EcUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import static org.apache.commons.lang.StringUtils.isBlank;

/**
 * Spring安全框架上下文工具类。
 *
 * @author JunJie
 */
public class SpringSecurityContextUtils {

    private static final Logger logger = LoggerFactory.getLogger(SpringSecurityContextUtils.class);

    /**
     * 得到当前登录用户对象信息。
     *
     * @return 对象<code>UserDetails</code>的子类
     */
    public static Object getLoginUser() {
        SecurityContext context = SecurityContextHolder.getContext();
        if (null == context) return null;

        Authentication au = context.getAuthentication();
        if (null == au) return null;

        return au.getPrincipal();
    }

    /**
     * 得到当前登录用户对象信息。
     * <p>
     * 返回值会被强转成给定的参数对象类型
     * </p>
     *
     * @param cls 返回的对象类型
     * @param <T> 登录用户泛型类型
     * @return 登录用户对象实例
     */
    public static <T extends UserDetails> T getLoginUser(Class<T> cls) {
        if (null == cls) return null;

        Object user = getLoginUser();
        if (null == user) return null;

        try {
            return cls.cast(user);
        } catch (Exception e) {
            logger.error(e.getMessage(), e);

            return null;
        }
    }

    /**
     * 获取当前登录的EC用户对象中的属性值。
     * <b>注意：此方法只适用于{@link EcUser}对象及其子类。</b>
     *
     * @param name 属性值对应的属性名
     * @return EC用户存放的属性值
     */
    public static Object getUserAttribute(String name) {
        if (isBlank(name)) return null;

        EcUser user = getLoginUser(EcUser.class);
        if (null == user) return null;

        return user.getAttribute(name);
    }
}

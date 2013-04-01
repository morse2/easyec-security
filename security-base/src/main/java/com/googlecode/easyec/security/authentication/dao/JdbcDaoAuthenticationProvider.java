package com.googlecode.easyec.security.authentication.dao;

import com.googlecode.easyec.security.userdetails.EcUser;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Map;
import java.util.Set;

/**
 * JDBC数据源认证提供者类。
 *
 * @author JunJie
 */
public class JdbcDaoAuthenticationProvider extends DaoAuthenticationProvider {

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        super.additionalAuthenticationChecks(userDetails, authentication);

        if (userDetails instanceof EcUser) {
            if (logger.isDebugEnabled()) {
                logger.debug("Print all of attributes if user just logon.");

                Map<String, Object> attributes = ((EcUser) userDetails).getAttributes();
                Set<String> keys = attributes.keySet();
                for (String key : keys) {
                    logger.debug("Attribute key: [" + key + "], value: [" + attributes.get(key) + "].");
                }
            }
        }
    }
}

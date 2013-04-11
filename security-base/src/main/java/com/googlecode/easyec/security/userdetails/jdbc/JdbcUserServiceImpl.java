package com.googlecode.easyec.security.userdetails.jdbc;

import com.googlecode.easyec.security.userdetails.EcUser;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.util.StringUtils;

import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * JDBC用户操作业务类。
 *
 * @author JunJie
 */
public class JdbcUserServiceImpl extends JdbcDaoImpl {

    private List<String> roles = new ArrayList<String>();

    public void setRoles(List<String> roles) {
        if (roles != null && !roles.isEmpty()) {
            this.roles.addAll(roles);
        }
    }

    @Override
    protected List<GrantedAuthority> loadGroupAuthorities(String username) {
        return Collections.emptyList();
    }

    @Override
    protected List<GrantedAuthority> loadUserAuthorities(String username) {
        return Collections.emptyList();
    }

    @Override
    protected UserDetails createUserDetails(String username, UserDetails userFromUserQuery, List<GrantedAuthority> combinedAuthorities) {
        String returnUsername = userFromUserQuery.getUsername();

        if (!isUsernameBasedPrimaryKey()) {
            returnUsername = username;
        }

        return new EcUser(returnUsername, userFromUserQuery.getPassword(), userFromUserQuery.isEnabled(),
                true, true, true, combinedAuthorities, ((EcUser) userFromUserQuery).getAttributes());
    }

    @Override
    protected List<UserDetails> loadUsersByUsername(String username) {
        return getJdbcTemplate().query(getUsersByUsernameQuery(), new String[] { username }, new RowMapper<UserDetails>() {

            public UserDetails mapRow(ResultSet rs, int rowNum) throws SQLException {
                String username = rs.getString(1);
                String password = rs.getString(2);
                boolean enabled = rs.getBoolean(3);

                EcUser user = new EcUser(username, password, enabled, true, true, true, AuthorityUtils.NO_AUTHORITIES);

                ResultSetMetaData metaData = rs.getMetaData();
                int count = metaData.getColumnCount();
                for (int i = 4; i <= count; i++) {
                    String colName = metaData.getColumnLabel(i);
                    if (!StringUtils.hasText(colName)) {
                        colName = metaData.getColumnName(i);
                    }

                    // add custom attribute
                    user.addAttribute(colName, rs.getObject(i));
                }

                return user;
            }

        });
    }

    @Override
    protected void addCustomAuthorities(String username, List<GrantedAuthority> authorities) {
        for (String role : roles) {
            authorities.add(new SimpleGrantedAuthority(getRolePrefix() + role));
        }
    }
}

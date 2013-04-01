package com.googlecode.easyec.security.userdetails;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static java.util.Collections.synchronizedMap;
import static java.util.Collections.unmodifiableMap;

/**
 * EC用户对象。
 *
 * @author JunJie
 */
public class EcUser extends User {

    private static final long serialVersionUID = 5668314396986722905L;
    private Map<String, Object> attributes = synchronizedMap(new HashMap<String, Object>(5));

    public EcUser(String username, String password, Collection<? extends GrantedAuthority> authorities) {
        super(username, password, authorities);
    }

    public EcUser(String username, String password, boolean enabled, boolean accountNonExpired,
                  boolean credentialsNonExpired, boolean accountNonLocked,
                  Collection<? extends GrantedAuthority> authorities) {
        super(username, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
    }

    public EcUser(String username, String password, boolean enabled, boolean accountNonExpired,
                  boolean credentialsNonExpired, boolean accountNonLocked,
                  Collection<? extends GrantedAuthority> authorities,
                  Map<String, Object> attributes) {
        super(username, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
        this.attributes.putAll(attributes);
    }

    public void addAttribute(String key, Object value) {
        attributes.put(key, value);
    }

    public boolean removeAttribute(String key) {
        return attributes.remove(key) != null;
    }

    public void removeAll() {
        attributes.clear();
    }

    public boolean hasAttribute(String key) {
        return attributes.containsKey(key);
    }

    public Object getAttribute(String key) {
        return attributes.get(key);
    }

    public Map<String, Object> getAttributes() {
        return unmodifiableMap(attributes);
    }

    @Override
    public boolean equals(Object rhs) {
        if (rhs instanceof User) {
            return getUsername().equals(((User) rhs).getUsername());
        }
        return false;
    }

    @Override
    public int hashCode() {
        return getUsername().hashCode();
    }
}

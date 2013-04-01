package com.googlecode.easyec.security.authentication.encoding;

import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.security.authentication.encoding.PasswordEncoder;

import static org.apache.commons.codec.binary.StringUtils.getBytesUtf16Le;
import static org.springframework.util.StringUtils.hasText;

/**
 * UTF-16小头密码加密类。
 *
 * @author JunJie
 */
public class Utf16LePasswordEncoder implements PasswordEncoder {

    public String encodePassword(String rawPass, Object salt) {
        return DigestUtils.shaHex(getBytesUtf16Le(rawPass));
    }

    public boolean isPasswordValid(String encPass, String rawPass, Object salt) {
        return hasText(encPass) && encPass.equals(encodePassword(rawPass, salt));
    }
}

package com.googlecode.easyec.security.authentication.encoding;

import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.apache.commons.codec.binary.StringUtils.getBytesUtf16Le;
import static org.springframework.util.StringUtils.hasText;

/**
 * UTF-16小头密码加密类。
 *
 * @author JunJie
 */
public class Utf16LePasswordEncoder implements PasswordEncoder, org.springframework.security.authentication.encoding.PasswordEncoder {

    public String encodePassword(String rawPass, Object salt) {
        return encode(rawPass);
    }

    public boolean isPasswordValid(String encPass, String rawPass, Object salt) {
        return matches(rawPass, encPass);
    }

    @Override
    public String encode(CharSequence rawPassword) {
        return DigestUtils.sha1Hex(getBytesUtf16Le(rawPassword.toString()));
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        return hasText(encodedPassword) && encodedPassword.equals(encode(rawPassword));
    }
}

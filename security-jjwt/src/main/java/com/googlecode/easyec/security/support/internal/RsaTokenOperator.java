package com.googlecode.easyec.security.support.internal;

import com.googlecode.easyec.security.support.TokenOperator;
import com.googlecode.easyec.security.utils.PemUtils;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.io.Resource;
import org.springframework.util.Assert;

import java.io.InputStream;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class RsaTokenOperator implements TokenOperator, InitializingBean {

    private Resource keyResource;
    private String password;

    // ----- key pairs
    private PublicKey publicKey;
    private PrivateKey privateKey;

    public RsaTokenOperator(Resource keyResource) {
        this.keyResource = keyResource;
    }

    public RsaTokenOperator(Resource keyResource, String password) {
        this.keyResource = keyResource;
        this.password = password;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    @Override
    public String encode(Claims claims) {
        return Jwts.builder()
            .setClaims(claims)
            .signWith(getPrivateKey())
            .compact();
    }

    @Override
    public Claims decode(String token) {
        return Jwts.parserBuilder()
            .setSigningKey(getPublicKey())
            .build()
            .parseClaimsJws(token)
            .getBody();
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(keyResource, "Cannot load resource: key-resource.");

        try (InputStream in = keyResource.getInputStream()) {
            Object o = PemUtils.read(in, "UTF-8");
            Assert.notNull(o, "Illegal PEM file.");

            PEMKeyPair pemKeyPair;
            if (o instanceof PEMEncryptedKeyPair) {
                Assert.notNull(password, "PEM is a encrypted key, but no password was present.");

                pemKeyPair = ((PEMEncryptedKeyPair) o).decryptKeyPair(
                    new JcePEMDecryptorProviderBuilder().build(password.toCharArray())
                );
            } else pemKeyPair = ((PEMKeyPair) o);

            KeyPair keyPair = new JcaPEMKeyConverter().getKeyPair(pemKeyPair);
            this.privateKey = keyPair.getPrivate();
            this.publicKey = keyPair.getPublic();
        }
    }
}

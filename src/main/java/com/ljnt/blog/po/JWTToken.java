package com.ljnt.blog.po;

import org.apache.shiro.authc.AuthenticationToken;

/**
 * @ Program       :  com.ljnt.blog.po.JWTToken
 * @ Description   :  配置token实体bean进行拓展，使其适应shiro框架
 * @ Author        :  lj
 * @ CreateDate    :  2020-2-4 17:56
 */
public class JWTToken implements AuthenticationToken {
    private String token;

    public JWTToken(String token) {
        this.token = token;
    }

    @Override
    public Object getPrincipal() {
        return token;
    }

    @Override
    public Object getCredentials() {
        return token;
    }
}

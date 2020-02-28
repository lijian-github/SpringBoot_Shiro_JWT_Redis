package com.ljnt.blog.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ljnt.blog.po.User;
import com.ljnt.blog.utils.RedisUtil;
import com.ljnt.blog.utils.TokenUtil;
import org.apache.shiro.authz.annotation.Logical;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

/**
 * @ Program       :  com.ljnt.blog.controller.LoginController
 * @ Description   :
 * @ Author        :  lj
 * @ CreateDate    :  2020-1-31 23:38
 */
@Controller
public class LoginController {
    @Autowired
    RedisUtil redisUtil;
    @PostMapping("/login")
    @ResponseBody
    public String login(String username,String password, HttpServletResponse response) throws JsonProcessingException {
        User user=new User();
        user.setUsername(username);
        user.setPassword(password);
        Long currentTimeMillis = System.currentTimeMillis();
        String token= TokenUtil.sign(username,currentTimeMillis);
        redisUtil.set(username,currentTimeMillis,TokenUtil.REFRESH_EXPIRE_TIME);
        response.setHeader("Authorization", token);
        response.setHeader("Access-Control-Expose-Headers", "Authorization");
        HashMap<String,Object> hs=new HashMap<>();
        hs.put("login","ok");
        ObjectMapper objectMapper=new ObjectMapper();
        return objectMapper.writeValueAsString(hs);
    };

    @PostMapping("/user")
    @RequiresRoles(logical = Logical.OR,value = {"user","admin"})
    @ResponseBody
    public String user() throws JsonProcessingException {
        HashMap<String,Object> hs=new HashMap<>();
        hs.put("info","成功访问user接口！");
        ObjectMapper objectMapper=new ObjectMapper();
        return objectMapper.writeValueAsString(hs);
    };

    @PostMapping("/admin")
    @RequiresRoles(logical = Logical.OR,value = {"admin"})
//    @ResponseBody
    public Object admin() throws JsonProcessingException {
//        HashMap<String,Object> hs=new HashMap<>();
//        hs.put("info","成功访问admin接口！");
//        ObjectMapper objectMapper=new ObjectMapper();
//        return objectMapper.writeValueAsString(hs);
        return "admin/blogs";
    };

}

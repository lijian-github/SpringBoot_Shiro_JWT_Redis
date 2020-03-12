package com.ljnt.blog.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ljnt.blog.po.Result;
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
    public Result login(String username, String password, HttpServletResponse response) throws JsonProcessingException {
        User user=new User();
        user.setUsername(username);
        user.setPassword(password);
        //去数据库拿密码验证用户名密码，这里直接验证
        if(username.equals("admin")){
            if (!password.equals("admin")){
                return new Result(400,"密码错误");
            }
        }else if (username.equals("user")){
            if (!password.equals("user")){
                return new Result(400,"密码错误");
            }
        }else{
            return new Result(400,"无此用户");
        }
        Long currentTimeMillis = System.currentTimeMillis();
        String token= TokenUtil.sign(username,currentTimeMillis);
        redisUtil.set(username,currentTimeMillis,TokenUtil.REFRESH_EXPIRE_TIME);
        response.setHeader("Authorization", token);
        response.setHeader("Access-Control-Expose-Headers", "Authorization");

        return new Result().OK();
    };

    @PostMapping("/user")
    @RequiresRoles(logical = Logical.OR,value = {"user","admin"})
    @ResponseBody
    public Result user(){
        return new Result(200,"成功访问user接口！");
    };

    @PostMapping("/admin")
    @RequiresRoles(logical = Logical.OR,value = {"admin"})
    @ResponseBody
    public Object admin() {
        return new Result(200,"成功访问admin接口！");
    };

}

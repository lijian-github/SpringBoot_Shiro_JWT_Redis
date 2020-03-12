package com.ljnt.blog.controller;

import com.ljnt.blog.po.Result;
import org.apache.shiro.authz.annotation.Logical;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class IndexController {
    @RequestMapping("/")
    public String index()  {
        return "index";
    }

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

package com.ljnt.blog.filter;

import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.ljnt.blog.po.JWTToken;
import com.ljnt.blog.po.Result;
import com.ljnt.blog.utils.RedisUtil;
import com.ljnt.blog.utils.TokenUtil;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter;
import org.apache.shiro.web.util.WebUtils;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @ Program       :  com.ljnt.blog.filter.JWTFilter
 * @ Description   :  自定义jwt过滤器，对token进行处理
 * @ Author        :  lj
 * @ CreateDate    :  2020-2-4 17:28
 */
public class JWTFilter extends BasicHttpAuthenticationFilter {

    /**
     * 判断是否允许通过
     * @param request
     * @param response
     * @param mappedValue
     * @return
     */
    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        System.out.println("isAccessAllowed方法");
        try{
            return executeLogin(request,response);
        }catch (Exception e){
            System.out.println("错误"+e);
            responseError(response,"shiro fail");
//            return false;
        }
        return false;
    }

    /**
     * 是否进行登录请求
     * @param request
     * @param response
     * @return
     */
    @Override
    protected boolean isLoginAttempt(ServletRequest request, ServletResponse response) {
        System.out.println("isLoginAttempt方法");
        String token=((HttpServletRequest)request).getHeader("token");
        if (token!=null){
            return true;
        }
        return false;
    }

    /**
     * 创建shiro token
     * @param request
     * @param response
     * @return
     */
    @Override
    protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) {
        String jwtToken = ((HttpServletRequest)request).getHeader("token");
        if(jwtToken!=null)
            return new JWTToken(jwtToken);

        return null;
    }

    /**
     * isAccessAllowed为false时调用，验证失败
     * @param request
     * @param response
     * @return
     * @throws Exception
     */
    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        System.out.println("onAccessDenied");
        responseError(response,"token verify fail");
        return false;
    }

    /**
     * 进行登录操作
     * @param request
     * @param response
     * @return
     * @throws Exception
     */
//    @Override
//    protected boolean executeLogin(ServletRequest request, ServletResponse response) throws Exception {
//        System.out.println("executeLogin方法");
//        String token=((HttpServletRequest)request).getHeader("token");
//        JWTToken jwtToken=new JWTToken(token);
//        getSubject(request,response).login(jwtToken);
//        return true;
//    }


    /**
     * shiro验证成功调用
     * @param token
     * @param subject
     * @param request
     * @param response
     * @return
     * @throws Exception
     */
    @Override
    protected boolean onLoginSuccess(AuthenticationToken token, Subject subject, ServletRequest request, ServletResponse response) throws Exception {
        System.out.println("onLoginSuccess：");
        String jwttoken= (String) token.getPrincipal();
        if (jwttoken!=null){
            try{
                if(TokenUtil.verify(jwttoken))
                    return true;
            }catch (Exception e){
                Throwable throwable = e.getCause();
                System.out.println("token验证："+e.getClass());
                if (e instanceof TokenExpiredException){
                    System.out.println("TokenExpiredException");
                    if (refreshToken(request, response)) {
                        return true;
                    }else {
                        return false;
                    }
                }
            }
        }
        return true;
    }



    /**
     * 拦截器的前置方法，此处进行跨域处理
     * @param request
     * @param response
     * @return
     * @throws Exception
     */
    @Override
    protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
        HttpServletRequest httpServletRequest= (HttpServletRequest) request;
        HttpServletResponse httpServletResponse= (HttpServletResponse) response;
        httpServletResponse.setHeader("Access-Control-Allow-Origin",httpServletRequest.getHeader("Origin"));
        httpServletResponse.setHeader("Access-Control-Allow-Methods","GET,POST,OPTIONS,PUT,DELETE");
        httpServletResponse.setHeader("Access-Control-Allow-Headers",httpServletRequest.getHeader("Access-Control-Resquest-Headers"));
        if (httpServletRequest.getMethod().equals(RequestMethod.OPTIONS.name())){
            httpServletResponse.setStatus(HttpStatus.OK.value());
        }

        //如果不带token，也不去验证shiro
        if (httpServletRequest.getHeader("token")==null){
            responseError(httpServletResponse,"no token");
            return false;
        }
        return super.preHandle(request,response);

    }


    /**
     * 刷新AccessToken，进行判断RefreshToken是否过期，未过期就返回新的AccessToken且继续正常访问
     * @param request
     * @param response
     * @return
     */
    private boolean refreshToken(ServletRequest request, ServletResponse response) {
        String token = ((HttpServletRequest)request).getHeader("token");
        String account = TokenUtil.getAccount(token);
        Long currentTime=TokenUtil.getCurrentTime(token);
        // 判断Redis中RefreshToken是否存在
        if (RedisUtil.hasKey(account)) {
            // Redis中RefreshToken还存在，获取RefreshToken的时间戳
            Long currentTimeMillisRedis = (Long) RedisUtil.get(account);
            // 获取当前AccessToken中的时间戳，与RefreshToken的时间戳对比，如果当前时间戳一致，进行AccessToken刷新
            if (currentTimeMillisRedis.equals(currentTime)) {
                // 获取当前最新时间戳
                Long currentTimeMillis =System.currentTimeMillis();
                RedisUtil.set(account, currentTimeMillis,
                        TokenUtil.REFRESH_EXPIRE_TIME);
                // 刷新AccessToken，设置时间戳为当前最新时间戳
                token = TokenUtil.sign(account, currentTimeMillis);
                // 将新刷新的AccessToken再次进行Shiro的登录
//                JWTToken jwtToken = new JWTToken(token);
//                getSubject(request, response).login(jwtToken);
                HttpServletResponse httpServletResponse = (HttpServletResponse) response;
                httpServletResponse.setHeader("Authorization", token);
                httpServletResponse.setHeader("Access-Control-Expose-Headers", "Authorization");
                return true;
            }
        }
        return false;
    }

    private void responseError(ServletResponse response,String msg){

        HttpServletResponse httpResponse = (HttpServletResponse) response;
        httpResponse.setCharacterEncoding("UTF-8");
        httpResponse.setContentType("application/json;charset=UTF-8");
        try {
            httpResponse.getWriter().append(new Result(400,msg).toString());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

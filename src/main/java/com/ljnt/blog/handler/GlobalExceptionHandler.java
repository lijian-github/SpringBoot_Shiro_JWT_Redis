package com.ljnt.blog.handler;

import com.ljnt.blog.po.Result;
import org.apache.shiro.ShiroException;
import org.apache.shiro.authz.UnauthenticatedException;
import org.apache.shiro.authz.UnauthorizedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.http.HttpStatus;
import org.springframework.validation.BindException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.NoHandlerFoundException;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@ControllerAdvice
public class GlobalExceptionHandler {

    private final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);
    /**
     * 异常处理
     * @param request
     * @param e
     * @return
     */
//    @ExceptionHandler({Exception.class, ShiroException.class})
//    public ModelAndView handleException(HttpServletRequest request, Exception e) throws Exception {
//        System.out.println("异常");
//        logger.error("Request URL : {} , Exception : {}", request.getRequestURL(), e);
//        ModelAndView mav = new ModelAndView();
//        mav.addObject("url", request.getRequestURL());
//        mav.addObject("exception", e);
//        mav.setViewName("error/error");
//
//        return mav;
//    }

    /**
     * 捕捉所有Shiro异常
     */
    @ExceptionHandler(ShiroException.class)
    public Result handle401(ShiroException e) {
        return new Result(401, "无权访问(Unauthorized):" + e.getMessage());
    }

    /**
     * 单独捕捉Shiro(UnauthorizedException)异常 该异常为访问有权限管控的请求而该用户没有所需权限所抛出的异常
     */
    @ExceptionHandler(UnauthorizedException.class)
    public Result handle401(UnauthorizedException e) {
        Result result = new Result();
        return new Result(401, "无权访问(Unauthorized):当前Subject没有此请求所需权限(" + e.getMessage() + ")");
    }

    /**
     * 单独捕捉Shiro(UnauthenticatedException)异常
     * 该异常为以游客身份访问有权限管控的请求无法对匿名主体进行授权，而授权失败所抛出的异常
     */
    @ExceptionHandler(UnauthenticatedException.class)
    public Result handle401(UnauthenticatedException e) {
        return new Result(401, "无权访问(Unauthorized):当前Subject是匿名Subject，请先登录(This subject is anonymous.)");
    }

    /**
     * 捕捉校验异常(BindException)
     */
    @ExceptionHandler(BindException.class)
    public Result validException(BindException e) {
        List<FieldError> fieldErrors = e.getBindingResult().getFieldErrors();
        Map<String, Object> error = this.getValidError(fieldErrors);
        return new Result(400, error.get("errorMsg").toString(), error.get("errorList"));
    }


    /**
     * 捕捉404异常
     */
    @ExceptionHandler(NoHandlerFoundException.class)
    public Result handle(NoHandlerFoundException e) {
        return new Result(404, e.getMessage());
    }

    /**
     * 捕捉其他所有异常
     */
    @ExceptionHandler(Exception.class)
    public Result globalException(HttpServletRequest request, Throwable ex) {
        return new Result(500, ex.toString() + ": " + ex.getMessage());
    }


    /**
     * 获取状态码
     */
    private HttpStatus getStatus(HttpServletRequest request) {
        Integer statusCode = (Integer) request.getAttribute("javax.servlet.error.status_code");
        if (statusCode == null) {
            return HttpStatus.INTERNAL_SERVER_ERROR;
        }
        return HttpStatus.valueOf(statusCode);
    }

    /**
     * 获取校验错误信息
     */
    private Map<String, Object> getValidError(List<FieldError> fieldErrors) {
        Map<String, Object> map = new HashMap<String, Object>(16);
        List<String> errorList = new ArrayList<String>();
        StringBuffer errorMsg = new StringBuffer("校验异常(ValidException):");
        for (FieldError error : fieldErrors) {
            errorList.add(error.getField() + "-" + error.getDefaultMessage());
            errorMsg.append(error.getField() + "-" + error.getDefaultMessage() + ".");
        }
        map.put("errorList", errorList);
        map.put("errorMsg", errorMsg);
        return map;
    }
}
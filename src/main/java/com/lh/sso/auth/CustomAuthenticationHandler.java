package com.lh.sso.auth;

import com.lh.common.sysmanager.SimpleEmpVo;
import com.lh.sdk.web.model.ResponseData;
import com.lh.sso.rest.entity.User;
import org.apereo.cas.authentication.AuthenticationException;
import org.apereo.cas.authentication.HandlerResult;
import org.apereo.cas.authentication.PreventedException;
import org.apereo.cas.authentication.UsernamePasswordCredential;
import org.apereo.cas.authentication.exceptions.AccountDisabledException;
import org.apereo.cas.authentication.exceptions.AccountPasswordMustChangeException;
import org.apereo.cas.authentication.handler.support.AbstractUsernamePasswordAuthenticationHandler;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.services.ServicesManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import javax.security.auth.login.AccountNotFoundException;
import java.lang.reflect.Field;
import java.security.GeneralSecurityException;
import java.util.HashMap;

/**
 * @author wangyongxin
 * @createAt 2018-05-08 下午4:34
 **/
@Component
public class CustomAuthenticationHandler extends AbstractUsernamePasswordAuthenticationHandler {

    @Value("${login.url}")
    private String loginUrl;

    private static final Logger LOGGER = LoggerFactory.getLogger(CustomAuthenticationHandler.class);

    private RestTemplate restTemplate = new RestTemplate();

    public CustomAuthenticationHandler(String name, ServicesManager servicesManager, PrincipalFactory principalFactory, Integer order) {
        super(name, servicesManager, principalFactory, order);
    }

    @Override
    protected HandlerResult authenticateUsernamePasswordInternal(UsernamePasswordCredential credential, String originPassword) throws GeneralSecurityException, PreventedException {
        User user = new User();
        user.setUsername(credential.getUsername());
        user.setPassword(credential.getPassword());
        HttpEntity<User> req = new HttpEntity(user);
        ResponseEntity<ResponseData<SimpleEmpVo>> responseEntity = restTemplate.exchange(loginUrl, HttpMethod.POST, req, new ParameterizedTypeReference<ResponseData<SimpleEmpVo>>() {
        });
        if(HttpStatus.OK.equals(responseEntity.getStatusCode())){
            ResponseData<SimpleEmpVo> res = responseEntity.getBody();
            if(ResponseData.AJAX_STATUS_SUCCESS.equals(res.getStatusCode())){
                try {
                    SimpleEmpVo userModel = res.getData();
                    Field[] fields = userModel.getClass().getDeclaredFields();
                    HashMap<String, Object> principalMap = new HashMap<>(fields.length);
                    for(Field field:fields){
                        field.setAccessible(true);
                        principalMap.put(field.getName(),field.get(userModel));
                    }
                    return createHandlerResult(credential,this.principalFactory.createPrincipal(credential.getUsername(),principalMap),null);
                } catch (IllegalAccessException e) {
                    LOGGER.error("登录认证过程异常",e);
                    throw new AuthenticationException("认证异常");
                }
            } else {
                LOGGER.debug("登录失败：" + res.getStatusInfo());
                switch (res.getStatusCode()){
                    case "4":
                        throw new AccountNotFoundException("用户名或密码错误");
                    case "5":
                        throw new AccountDisabledException("账户已禁用");
                    case "6":
                        throw new AccountDisabledException("账户已禁用");
                    case "7":
                        throw new AccountPasswordMustChangeException("您的密码是初始化密码，请您修改密码");
                    default:
                        throw new AuthenticationException(res.getStatusInfo());
                }
            }
        } else {
            throw new AuthenticationException("认证异常:"+responseEntity.getStatusCode());
        }
    }
}

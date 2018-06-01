package com.lh.sso.auth;

import com.lh.sdk.utils.Md5Encoder;
import com.lh.sdk.web.model.ResponseData;
import com.lh.sso.rest.entity.User;
import com.lh.sso.rest.entity.UserModel;
import org.apereo.cas.authentication.AuthenticationException;
import org.apereo.cas.authentication.HandlerResult;
import org.apereo.cas.authentication.PreventedException;
import org.apereo.cas.authentication.UsernamePasswordCredential;
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
        user.setPassword(Md5Encoder.encodePassword(credential.getPassword()));
        try {
            HttpEntity<User> req = new HttpEntity(user);
            ResponseEntity<ResponseData<UserModel>> responseEntity = restTemplate.exchange(loginUrl, HttpMethod.POST, req, new ParameterizedTypeReference<ResponseData<UserModel>>() {
            });
            if(HttpStatus.OK.equals(responseEntity.getStatusCode())){
                ResponseData<UserModel> res = responseEntity.getBody();
                if(ResponseData.AJAX_STATUS_SUCCESS.equals(res.getStatusCode())){
                    UserModel userModel = res.getData();
                    Field[] fields = userModel.getClass().getDeclaredFields();
                    HashMap<String, Object> principalMap = new HashMap<>();
                    for(Field field:fields){
                        field.setAccessible(true);
                        principalMap.put(field.getName(),field.get(userModel));
                    }
                    return createHandlerResult(credential,this.principalFactory.createPrincipal(credential.getUsername(),principalMap),null);
                } else {
                    throw new AuthenticationException(res.getStatusInfo());
                }
            } else {
                throw new AuthenticationException("认证异常:"+responseEntity.getStatusCode());
            }
        } catch (Exception e) {
            LOGGER.error("rest认证失败",e);
            throw new AuthenticationException("认证异常");
        }
    }
}

package com.lh.sso.aop;

import com.alibaba.fastjson.JSON;
import com.lh.sdk.web.model.ResponseData;
import org.apereo.cas.CentralAuthenticationService;
import org.apereo.cas.authentication.AuthenticationException;
import org.apereo.cas.authentication.AuthenticationResult;
import org.apereo.cas.authentication.AuthenticationSystemSupport;
import org.apereo.cas.authentication.Credential;
import org.apereo.cas.authentication.exceptions.AccountDisabledException;
import org.apereo.cas.authentication.exceptions.AccountPasswordMustChangeException;
import org.apereo.cas.authentication.principal.Service;
import org.apereo.cas.authentication.principal.ServiceFactory;
import org.apereo.cas.support.rest.BadRequestException;
import org.apereo.cas.support.rest.CredentialFactory;
import org.apereo.cas.support.rest.factory.DefaultCredentialFactory;
import org.apereo.cas.support.rest.factory.TicketGrantingTicketResourceEntityResponseFactory;
import org.apereo.cas.ticket.TicketGrantingTicket;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;

import javax.security.auth.login.AccountNotFoundException;
import javax.servlet.http.HttpServletRequest;

/**
 * @author wangyongxin
 * @createAt 2018-07-06 上午10:49
 **/
@Component
@Aspect
public class RestResponseAspect {

    private static final Logger LOGGER = LoggerFactory.getLogger(RestResponseAspect.class);

    @Autowired
    @Qualifier("centralAuthenticationService")
    private CentralAuthenticationService centralAuthenticationService;

    @Autowired(required = false)
    @Qualifier("defaultAuthenticationSystemSupport")
    private AuthenticationSystemSupport authenticationSystemSupport;

    @Autowired(required = false)
    private CredentialFactory credentialFactory = new DefaultCredentialFactory();

    @Autowired
    @Qualifier("webApplicationServiceFactory")
    private ServiceFactory webApplicationServiceFactory;
    
    @Autowired
    private TicketGrantingTicketResourceEntityResponseFactory ticketGrantingTicketResourceEntityResponseFactory;

    @Around("execution(* org.apereo.cas.support.rest.resources.TicketGrantingTicketResource.createTicketGrantingTicket(..))")
    public Object RestResponse(ProceedingJoinPoint joinPoint) {
        Object[] args = joinPoint.getArgs();
        return createTicketGrantingTicket((MultiValueMap<String, String>) args[0],(HttpServletRequest)args[1]);
    }

    public ResponseEntity<String> createTicketGrantingTicket(final MultiValueMap<String, String> requestBody,
                                                             final HttpServletRequest request){
        try {
            final TicketGrantingTicket tgtId = createTicketGrantingTicketForRequest(requestBody, request);
            return createResponseEntityForTicket(request, tgtId);
        } catch (final AuthenticationException e) {
            LOGGER.error(e.getMessage(), e);
            return handleAuthenticationException(e);
        } catch (final BadRequestException e) {
            LOGGER.error(e.getMessage(), e);
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        } catch (final Exception e) {
            LOGGER.error(e.getMessage(), e);
            return new ResponseEntity<>(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    private ResponseEntity<String> handleAuthenticationException(AuthenticationException e) {
        Class<? extends Throwable> aClass = e.getHandlerErrors().values().stream().findFirst().get();
        String statusCode = "0";
        String statusInfo = "";
        if(AccountNotFoundException.class.equals(aClass)){
            statusCode = "4";
            statusInfo = "用户名或密码错误";
        }else if(AccountDisabledException.class.equals(aClass)) {
            statusCode = "5";
            statusInfo = "账户已禁用";
        }else if(AccountPasswordMustChangeException.class.equals(aClass)){
            statusCode = "7";
            statusInfo = "您的密码是初始化密码，请您修改密码";
        } else {
            statusInfo = "登录失败，请联系管理员";
        }
        return new ResponseEntity<>(JSON.toJSONString(new ResponseData<>(statusCode,statusInfo)), HttpStatus.UNAUTHORIZED);
    }

    protected TicketGrantingTicket createTicketGrantingTicketForRequest(final MultiValueMap<String, String> requestBody,
                                                                        final HttpServletRequest request) {
        final Credential credential = this.credentialFactory.fromRequestBody(requestBody);
        final Service service = this.webApplicationServiceFactory.createService(request);
        final AuthenticationResult authenticationResult =
                authenticationSystemSupport.handleAndFinalizeSingleAuthenticationTransaction(service, credential);
        return centralAuthenticationService.createTicketGrantingTicket(authenticationResult);
    }

    protected ResponseEntity<String> createResponseEntityForTicket(final HttpServletRequest request,
                                                                   final TicketGrantingTicket tgtId) throws Exception {
        return this.ticketGrantingTicketResourceEntityResponseFactory.build(tgtId, request);
    }

}

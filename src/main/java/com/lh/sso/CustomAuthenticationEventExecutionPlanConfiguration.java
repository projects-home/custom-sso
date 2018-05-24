package com.lh.sso;

import com.lh.sso.auth.CustomAuthenticationHandler;
import org.apereo.cas.authentication.AuthenticationEventExecutionPlan;
import org.apereo.cas.authentication.AuthenticationEventExecutionPlanConfigurer;
import org.apereo.cas.authentication.principal.DefaultPrincipalFactory;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.services.ServicesManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * @author wangyongxin
 * @createAt 2018-05-08 下午6:37
 **/
@Configuration("customAuthenticationEventExecutionPlanConfiguration")
@EnableConfigurationProperties(CasConfigurationProperties.class)
public class CustomAuthenticationEventExecutionPlanConfiguration implements AuthenticationEventExecutionPlanConfigurer {

    @Autowired
    @Qualifier("servicesManager")
    private ServicesManager servicesManager;

    @Bean
    public CustomAuthenticationHandler authenticationHandler(){
        return new CustomAuthenticationHandler("",servicesManager,new DefaultPrincipalFactory(),1);
    }

    @Override
    public void configureAuthenticationExecutionPlan(AuthenticationEventExecutionPlan authenticationEventExecutionPlan) {
        authenticationEventExecutionPlan.registerAuthenticationHandler(authenticationHandler());
    }
}

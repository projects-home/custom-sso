package com.lh.sso.token;

import org.apereo.cas.config.TokenCoreConfiguration;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.ticket.ExpirationPolicy;
import org.apereo.cas.token.JWTTokenTicketBuilder;
import org.apereo.cas.token.TokenTicketBuilder;
import org.jasig.cas.client.validation.AbstractUrlBasedTicketValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * @author wangyongxin
 * @createAt 2018-06-04 下午4:14
 **/
@Configuration("tokenCoreConfiguration")
@EnableConfigurationProperties(CasConfigurationProperties.class)
public class CustomTokenCoreConfiguration extends TokenCoreConfiguration {
    @Autowired
    private CasConfigurationProperties casProperties;

    @Autowired
    @Qualifier("casClientTicketValidator")
    private AbstractUrlBasedTicketValidator casClientTicketValidator;

    @Autowired
    @Qualifier("grantingTicketExpirationPolicy")
    private ExpirationPolicy grantingTicketExpirationPolicy;

    @Bean
    @Override
    public TokenTicketBuilder tokenTicketBuilder(){
        return new CustomJwtTokenTicketBuilder(casClientTicketValidator,
                casProperties.getServer().getPrefix(),
                tokenCipherExecutor(),
                grantingTicketExpirationPolicy);
    }
}

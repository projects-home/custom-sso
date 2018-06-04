package com.lh.sso.token;

import com.alibaba.fastjson.JSON;
import org.apereo.cas.CipherExecutor;
import org.apereo.cas.authentication.Authentication;
import org.apereo.cas.ticket.ExpirationPolicy;
import org.apereo.cas.ticket.TicketGrantingTicket;
import org.apereo.cas.token.JWTTokenTicketBuilder;
import org.hjson.JsonValue;
import org.hjson.Stringify;
import org.jasig.cas.client.validation.AbstractUrlBasedTicketValidator;
import org.jasig.cas.client.validation.TicketValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.ZonedDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * @author wangyongxin
 * @createAt 2018-06-04 下午3:09
 **/
public class CustomJwtTokenTicketBuilder extends JWTTokenTicketBuilder {

    private static final Logger LOGGER = LoggerFactory.getLogger(CustomJwtTokenTicketBuilder.class);

    private final TicketValidator ticketValidator;
    private final String casSeverPrefix;
    private final CipherExecutor<String, String> tokenCipherExecutor;
    private final ExpirationPolicy expirationPolicy;

    public CustomJwtTokenTicketBuilder(AbstractUrlBasedTicketValidator ticketValidator, String casSeverPrefix, CipherExecutor<String, String> tokenCipherExecutor, ExpirationPolicy expirationPolicy) {
        super(ticketValidator,casSeverPrefix,tokenCipherExecutor,expirationPolicy);
        this.ticketValidator = ticketValidator;
        this.casSeverPrefix = casSeverPrefix;
        this.tokenCipherExecutor = tokenCipherExecutor;
        this.expirationPolicy = expirationPolicy;
    }

    @Override
    public String build(TicketGrantingTicket ticketGrantingTicket) {
        try {
            final Authentication authentication = ticketGrantingTicket.getAuthentication();
            final Map<String, Object> attributes = new LinkedHashMap<>(authentication.getPrincipal().getAttributes());

            final ZonedDateTime dt = ZonedDateTime.now().plusSeconds(expirationPolicy.getTimeToLive());
            final Date validUntilDate = Date.from(dt.toInstant());
            return buildJwt(ticketGrantingTicket.getId(), casSeverPrefix,
                    Date.from(ticketGrantingTicket.getCreationTime().toInstant()),
                    authentication.getPrincipal().getId(),
                    validUntilDate, attributes);
        } catch (final Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    private String buildJwt(final String jwtId, final String audience,
                            final Date issueDate, final String subject,
                            final Date validUntilDate, final Map<String, Object> attributes) {
        final Map<String,Object> jwtTokenInfo = new HashMap<>();
        jwtTokenInfo.put("jti",jwtId);
        jwtTokenInfo.put("issueTime",issueDate);
        jwtTokenInfo.put("expirationTime",validUntilDate);
        attributes.forEach(jwtTokenInfo::put);
        final String jwtJson = JSON.toJSONString(jwtTokenInfo);
        LOGGER.info("Generated JWT [{}]", JsonValue.readJSON(jwtJson).toString(Stringify.FORMATTED));
        if (tokenCipherExecutor.isEnabled()) {
            return tokenCipherExecutor.encode(jwtJson);
        }
        final String token = new PlainJwt(jwtTokenInfo).serialize();
        return token;
    }
}

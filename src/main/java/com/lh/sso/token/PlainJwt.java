package com.lh.sso.token;

import com.alibaba.fastjson.JSON;

import java.nio.charset.Charset;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * @author wangyongxin
 * @createAt 2018-06-04 下午3:51
 **/
public class PlainJwt {

    private final Map<String,Object> payload;
    private final Map<String,Object> header;

    public PlainJwt(Map<String,Object> jwtTokenInfo) {
        this(null,jwtTokenInfo);
    }

    public PlainJwt(Map<String,Object> header,Map<String,Object> jwtTokenInfo) {
        this.payload = jwtTokenInfo;
        if(header!=null&&header.size()>0){
            this.header = header;
        } else {
            Map<String,Object> defaultHeader = new HashMap<>();
            defaultHeader.put("alg","none");
            this.header = defaultHeader;
        }
    }


    public String serialize() {
        return String.format("%s.%s", Base64.getEncoder().encodeToString(JSON.toJSONString(this.header).getBytes(Charset.forName("utf-8"))), Base64.getEncoder().encodeToString(JSON.toJSONString(this.payload).getBytes(Charset.forName("utf-8"))));
    }
}

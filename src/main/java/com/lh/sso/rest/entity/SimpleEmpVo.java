package com.lh.sso.rest.entity;

/**
 * @author wangyongxin
 * @createAt 2018-06-01 下午3:18
 **/
public class SimpleEmpVo {

    private String userName;
    private String userId;
    private String userCode;

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getUserCode() {
        return userCode;
    }

    public void setUserCode(String userCode) {
        this.userCode = userCode;
    }
}

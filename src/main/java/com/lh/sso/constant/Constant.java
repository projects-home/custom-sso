package com.lh.sso.constant;

/**
 * @author wangyongxin
 * @createAt 2018-07-11 下午3:44
 **/
public class Constant {
    private Constant(){}

    /**
     * 用户状态：7，需要修改密码；1，正常
     */
    public static final String NEED_CHANGE_PASSWORD_FLAG = "7";
    /**
     * 用户状态key
     */
    public static final String USER_STATUS_KEY = "userStatus";
    /**
     * 用户id Key
     */
    public static final String USER_ID_KEY = "userId";
}

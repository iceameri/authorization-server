package com.jw.authorizationserver.constants;

import org.springframework.security.oauth2.core.AuthorizationGrantType;

public class OAuth2Constants {
    public static final String CLIENT_ID = "client_id";

    public static final String CLIENT_SECRET = "client_secret";

    public static final String GRANT_TYPE = "grant_type";;

    public static final String RESPONSE_TYPE = "response_type";

    public static final String SCOPE = "scope";

    public static final String REDIRECT_URI = "redirect_uri";

    public static final String CODE = "code";

    public static final String USERNAME = "username";

    public static final String PASSWORD = "password";

    public static final String AUTHORIZATION_CODE = "authorization_code";

    public static final String REFRESH_TOKEN = AuthorizationGrantType.REFRESH_TOKEN.getValue();
}

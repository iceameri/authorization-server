package com.jw.authorizationserver.dto;

public record OAuth2TokenResponse(String accessToken, String refreshToken, String scope, String idToken,
                                  String tokenType, int expiresIn) {
}

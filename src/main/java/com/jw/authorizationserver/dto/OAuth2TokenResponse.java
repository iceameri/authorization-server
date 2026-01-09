package com.jw.authorizationserver.dto;

import lombok.Builder;

public record OAuth2TokenResponse(
        String accessToken,
        String refreshToken,
        String scope,
        String idToken,
        String tokenType,
        int expiresIn
) {
    @Builder
    public OAuth2TokenResponse {
    }
}

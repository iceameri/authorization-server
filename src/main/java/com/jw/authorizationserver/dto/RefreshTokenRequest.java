package com.jw.authorizationserver.dto;

public record RefreshTokenRequest(
        String refreshToken
) {
}
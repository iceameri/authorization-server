package com.jw.authorizationserver.controller;

import com.jw.authorizationserver.constants.OAuth2Constants;
import com.jw.authorizationserver.dto.OAuth2TokenResponse;
import com.jw.authorizationserver.dto.RefreshTokenRequest;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.util.Optional;

@Slf4j
@RestController
@RequestMapping(value = AuthController.BASE_PATH)
public class AuthController {
    public static final String BASE_PATH = "/auth";

    @Value("${test.service.client.id}")
    private String TEST_SERVICE_CLIENT_ID;

    @Value("${test.service.client.secret}")
    private String TEST_SERVICE_CLIENT_SECRET;

    /**
     * 받은 authorization_code로 /oauth2/token 요청
     * access_token 받아서 저장하거나 출력
     */
    @GetMapping("/callback")
    public ResponseEntity<Object> callback(@RequestParam String code) {
        log.info("code = {}", code);
        return ResponseEntity.ok(code);
    }

    @GetMapping("/authorized")
    public ResponseEntity<OAuth2TokenResponse> redirectResourceServer(
            final HttpServletRequest request,
            @RequestHeader final HttpHeaders httpHeaders,
            @RequestParam(name = OAuth2Constants.CLIENT_ID, required = false) String clientId,
            @RequestParam(name = OAuth2Constants.CLIENT_SECRET, required = false) String clientSecret,
            @RequestParam(name = OAuth2Constants.CODE) final String code,
            @RequestParam(name = OAuth2Constants.REDIRECT_URI, required = false) final String redirectUri
    ) {
        MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
        requestBody.add(OAuth2Constants.GRANT_TYPE, OAuth2Constants.AUTHORIZATION_CODE);
        requestBody.add(OAuth2Constants.CODE, code);

        if (redirectUri == null || redirectUri.isBlank()) {
            requestBody.add(OAuth2Constants.REDIRECT_URI, request.getRequestURL().toString());
        } else {
            requestBody.add(OAuth2Constants.REDIRECT_URI, redirectUri.trim());
        }

        HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(requestBody, this.getHttpHeadersBasicAuthorization(httpHeaders, clientId, clientSecret));

        return new RestTemplate().postForEntity(this.getTokenEndPointUrl(request), requestEntity, OAuth2TokenResponse.class);
    }

    @PostMapping(value = "/token/refresh")
    public ResponseEntity<OAuth2AccessToken> webRefresh(
            final HttpServletRequest request,
            @RequestHeader final HttpHeaders httpHeaders,
            @RequestParam(name = OAuth2Constants.CLIENT_ID, required = false) String clientId,
            @RequestParam(name = OAuth2Constants.CLIENT_SECRET, required = false) String clientSecret,
            @RequestBody final RefreshTokenRequest refreshTokenRequest
    ) {
        MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
        requestBody.add(OAuth2Constants.GRANT_TYPE, OAuth2Constants.REFRESH_TOKEN);
        requestBody.add(AuthorizationGrantType.REFRESH_TOKEN.getValue(), refreshTokenRequest.refreshToken());

        HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(requestBody, this.getHttpHeadersBasicAuthorization(httpHeaders, clientId, clientSecret));
        return new RestTemplate().postForEntity(this.getTokenEndPointUrl(request), requestEntity, OAuth2AccessToken.class);
    }

    private HttpHeaders getHttpHeadersBasicAuthorization(final HttpHeaders httpHeaders,
                                                         String clientId,
                                                         String clientSecret) {
        httpHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        httpHeaders.setBasicAuth(
                Optional.ofNullable(clientId).orElse(this.TEST_SERVICE_CLIENT_ID),
                Optional.ofNullable(clientSecret).orElse(this.TEST_SERVICE_CLIENT_SECRET)
        );
        return httpHeaders;
    }

    private String getTokenEndPointUrl(final HttpServletRequest request) {
        return String.format("%s://%s:%d/oauth/token", request.getScheme(), request.getServerName(), request.getServerPort());
    }
}

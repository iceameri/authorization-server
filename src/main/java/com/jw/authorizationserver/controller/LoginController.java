package com.jw.authorizationserver.controller;

import com.jw.authorizationserver.dto.OAuth2TokenResponse;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping(value = LoginController.BASE_PATH)
public class LoginController {
    public static final String BASE_PATH = "/auth";

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
            @RequestHeader final HttpHeaders reqHeaders,
            @RequestParam(name = "code") final String code,
            @RequestParam(name = "redirect_uri", required = false) final String redirectUri
    ) {
        reqHeaders.setBasicAuth("test-client", "P@$$w0rd1!");
        reqHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
        requestBody.add("grant_type", "authorization_code");
        requestBody.add("code", code);

        if (redirectUri == null || redirectUri.isBlank()) {
            requestBody.add("`redirect_uri`", request.getRequestURL().toString());
        } else {
            requestBody.add("redirect_uri", redirectUri.trim());
        }

        HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(requestBody, reqHeaders);

        return new RestTemplate().postForEntity(
                String.format("%s://%s:%d/oauth/token", request.getScheme(), request.getServerName(), request.getServerPort()),
                requestEntity,
                OAuth2TokenResponse.class);
    }

    @GetMapping(value = "/userinfo", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> userInfo(@AuthenticationPrincipal Jwt jwt) {
        log.info("email = {}", jwt.getClaimAsString("email"));
        Map<String, Object> userInfo = new HashMap<>();
        userInfo.put("email", "user@example.com");
        userInfo.put("name", "Test User");
        return userInfo;
    }

}

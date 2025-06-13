package com.jw.authorizationserver.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

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
}

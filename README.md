
* 로그인화면 URL
`curl -X GET "http://localhost:9090/oauth2/authorize
?response_type=code
&client_id=test-client
&redirect_uri=http://localhost:9090/auth/callback&scope=openid%20profile%20email"`
`(GET http://local/host:9090/oauth2/authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost:9090/auth/callback&scope=openid profile email)`

* Token 발급
`curl -X POST http://localhost:9090/oauth2/token \
-H "Content-Type: application/x-www-form-urlencoded" \
-d "grant_type=authorization_code" \
-d "code={AUTH_CODE}" \
-d "redirect_uri=http://localhost:9090/auth/callback" \
-d "user_id={user_id}" \
-d "password={password}"`

* refresh_token 재발급 (옵션필요)
`curl -X POST http://localhost:9090/oauth2/token \
-H "Content-Type: application/x-www-form-urlencoded" \
-d "grant_type=refresh_token" \
-d "refresh_token={refresh_token}"`

* client_credentials Token 발급
`curl -X POST http://localhost:9090/oauth2/token \
-H "Content-Type: application/x-www-form-urlencoded" \
-d "grant_type=client_credentials"`

* JWT 정보
`curl -X GET http://localhost:9090/oauth2/jwks`

* 토큰 무효화
`curl -X POST http://localhost:9090/oauth2/revoke \
-H "Content-Type: application/x-www-form-urlencoded" \
-d token={access_token OR refresh_token}`

* 토큰 유효성 검사
`curl -X POST http://localhost:9090/oauth2/introspect \
-H "Content-Type: application/x-www-form-urlencoded" \
-d token={access_token OR refresh_token}`


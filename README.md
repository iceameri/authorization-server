# Authorization Server (Spring Authorization Server)

Spring Authorization Server 기반의 OAuth 2.1 / OIDC 토큰 발급 서버다. \
Authorization Code, Refresh Token, Client Credentials 그랜트 타입을 지원하며, 
토큰 무효화(revocation), 토큰 유효성 검사(introspection), JWK 공개 키 제공(jwks) 엔드포인트를 포함한다.


## OAuth 2.0의 Opaque Token
-  OAuth 2.0 에서 Opaque Token이 기본이라고 명시된 적은 없다. 하지만 기본 전제에 가깝다.
- RFC 6749 (OAuth 2.0 Core) 에서 **Access Token은 “단순 문자열(string)”**로만 정의한다.\
형식에 대한 규정이 없으나 위의 내용에서 가장 자연스러운 구현이 Opaque Token 이다.(스펙적 관점)
- 역사적으로 OAuth2.0(2012~2014)보다 JWT(2015)가 느리다.

## OAuth 2.0 -> 2.1 버전업이 된 핵심계기
1. OAuth 2.0의 복잡성 → OAuth 2.1 단순화\
10개 넘는 Grant Type과 옵션이 있었지만 불필요 기능들이 폐기되었다.\
그 중 `Implicit Grant`와 `Password Grant` 제거되면서 
프론트에서 Access Token을 클라이언트로 직접 받을 수 없게되고 서버가 JWT를 만들어주는 패턴이 일반화 되었다.

2. Stateful -> Stateless\
Opaque Token 랜덤 문자열을 검증하려면
```
    Client → Resource Server → Authorization Server(introspection)
```
핸덤 문자열이기때문에 사용자정보,권한, 만료시간, 발급 정보 등 아무것도 알수 없다.\
이로인해 서버에 전달되어 검증이 필요하며 서비스가 많으면 병목이 발생한다.\
JWT는 자체 서명이 포함되어있어서 리소스 서버가 토큰 단독 검증이 가능하다. 그렇기 때문에 성능상에 이점이 있다.

> 하지만 보안이 중요한 곳에서는 여전히 Opaque Token이 사용된다.\
> 중요한 정보들은 JWT 내에 저장하지 않으므로 보안을 위한 권한체크는 해당 정보를 조회는 서버와의 통신을 할 수 밖에 없기 때문에 
해당 로직을 추가하는 것이 곧 Stateful 서버가 되는 것이므로 설계 초기부터 의사결정이 필요하다.\

> 쿠팡사태와 같이 토큰을 탈취하게 되면 서버쪽에서는 손쓸방법이 없기 때문에 인증을 가볍게 사용할 수 있는 서버는 JWT를 사용하고
> 사업측면에서 매출이 영향에 큰 서버에는 Opaque Token으로 사용해야한다.\
> 최적화 위해서는 Local Cache -> Global Cache -> DB 순으로 데이터를 조회하면 되지않을까 싶다.

## OIDC 와 Access Token 차이
OIDC: 로그인 성공 후 프론트앤드, 클라이언트가 사용자 정보 확인, API 호출에 사용하면 안됨
Access Token: Resource Server 검증 대상

### 참고사항
jwt 토큰의 위험성은 토큰이 탈취당하고 만료시간까지 소멸시키는 방법이 불가하다.\
테스트의 용이성을 위해 어드민권한을 담은 만료시간이 긴 토큰은 절대 만들면 안된다.\
휴먼에러로 인한 취약성을 항상 조심해야 한다.

3. 비용 절감
세션 기반/opaque token 기반은 서버가 토큰 상태를 저장해야 하므로
OAuth 2.0 내장되어있는 RedisTokenStore를 사용한다.\
Redis 같은 세션 저장소 구축 비용이 발생하고 저장소 장애로 인한 전체 로그인 서비스 중단을 막기 위하여 
안정적인 서비스를 위해 클러스터링을 하는 등 유지 보수 비용 또한 증가한다.
   
4. 마이크로서비스 구조에서 인증 정보 동기화가 필요 없음\
세션 기반은 여러 서비스가 같은 세션 상태 접근필요하고 서비스 간 인증 전달도 어려운데에 반해
JWT는 모든 서비스가 별도 호출 없이 토큰만 검증하여 이늦어 상태 공유문제가 사라지고
Gateway, API Server, Microservice 모두 도일 방식으로 사용하기 때문에 Mesh 구조에서 필수적인 요소다.

5. 외부 서비스 및 모바일,웹,외부 파트너 와 통합이 쉬움\
  role, scope, user id 포함 가능하여 외부 클라이언트가 바로 검증 및 파싱가능하다.
   
6. 운영 및 장애 대응 측면에서 단순함\
Opaque Token 기반은 서버 장애 시 세션 복구 및 세션 동기화 문제가 있고 Redis 장애 시 전체 로그인 중단이 발생한다.
JWT는 토큰 자체에 상태가 포함되어있기 때문에 운영이 단순해진다.
   
## 주요 기능
- OAuth 2.1 Authorization Code 그랜트로 액세스 토큰/리프레시 토큰 발급
- Client Credentials 그랜트 지원
- Refresh Token 재발급 지원
- JWKS 공개 키 제공(`/oauth2/jwks`)
- 토큰 무효화(`/oauth2/revoke`)
- 토큰 유효성 검사(`/oauth2/introspect`)

## 기술 스택
- Java 17+ (권장)
- Spring Boot 3.x
- Spring Authorization Server
- MS SQL (`docker-compose.yml` 참고) (스키마는 `src/main/resources/schema.sql` 참고)

기본 포트 및 콜백
- 서버 포트: `http://localhost:9090`
- 콜백 URL(예시): `http://localhost:9090/auth/callback`

애플리케이션 설정은 `src\main\resources\application.yml`에서 변경할 수 있습니다.

## 엔드포인트 요약 및 예제

아래 예제는 기본 포트(9090) 기준입니다. 필요 시 `client_id`, `redirect_uri` 등을 환경에 맞게 수정하세요.

### 1) 로그인 화면 / 인가 코드 요청 (Authorization Code)
```
GET http://localhost:9090/oauth2/authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost:9090/auth/callback&scope=openid%20profile%20email
```
또는 cURL:
```
curl -X GET "http://localhost:9090/oauth2/authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost:9090/auth/callback&scope=openid%20profile%20email"
```

브라우저로 접근하면 로그인 페이지로 리다이렉트되고 인증 성공 시 `redirect_uri`로 `code`가 전달된다.

### 2) 토큰 발급 (Authorization Code → Access/Refresh Token)
```
curl -X POST http://localhost:9090/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code={AUTH_CODE}" \
  -d "redirect_uri=http://localhost:9090/auth/callback" \
  -d "user_id={user_id}" \
  -d "password={password}"
```

응답은 `access_token`, `refresh_token`, `expires_in`, `scope`, `token_type` 등을 포함한다.

### 3) Refresh Token 재발급
```
curl -X POST http://localhost:9090/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "refresh_token={refresh_token}"
```

### 4) Client Credentials 토큰 발급
```
curl -X POST http://localhost:9090/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials"
```

### 5) JWK 공개 키 목록
```
curl -X GET http://localhost:9090/oauth2/jwks
```

### 6) 토큰 무효화 (Revocation)
```
curl -X POST http://localhost:9090/oauth2/revoke \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d token={access_token OR refresh_token}
```

### 7) 토큰 유효성 검사 (Introspection)
```
curl -X POST http://localhost:9090/oauth2/introspect \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d token={access_token OR refresh_token}
```

## 이전 정리
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

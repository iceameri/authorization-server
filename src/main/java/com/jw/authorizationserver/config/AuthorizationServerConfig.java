package com.jw.authorizationserver.config;

import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jw.authorizationserver.service.CustomUserDetails;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.session.HttpSessionEventPublisher;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;

@Configuration
public class AuthorizationServerConfig {

    /**
     * /oauth2/authorize, /oauth2/token, /oauth2/jwks 엔드포인트 처리
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                OAuth2AuthorizationServerConfigurer.authorizationServer();

        http
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                // OAuth2 인증 서버 설정 포함 (authorize, token, etc.)
                .with(authorizationServerConfigurer, configurer ->
                        configurer.oidc(Customizer.withDefaults()) // OIDC 1.0 활성화
                )
                // 모든 요청 인증 필요
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().authenticated()
                )
                // 인증 실패 시 로그인 페이지로 이동
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
                );

        return http.build();
    }

    /**
     * POST /oauth2/revoke?token={ACCESS_OR_REFRESH_TOKEN} Basic base64({client_id}:{client_secret})
     * /revoke 무효화 API
     * <br>
     * POST /oauth2/introspect?token={ACCESS_OR_REFRESH_TOKEN} Basic base64({client_id}:{client_secret})
     * /introspect 토큰 유효성 검사
     * tokenSettings().reuseRefreshTokens(false) 설정되어있어야 RefreshToken 이 재발급
     * <br>
     * grant_type = password 는 기본적으로 Deprecated 되어있고 단순한 사용은 위험이 따르고 2단계 인증과 같은 자격증명 필요(<a href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics-19#section-2.4">...</a>)
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        /*AuthorizationGrantType.DEVICE_CODE AuthorizationGrantType.CLIENT_CREDENTIALS*/
        return AuthorizationServerSettings.builder().build(); // 기본값 사용
    }

    /**
     * 리소스 소유자가 클라이언트 에게 부여한 권한을 보유하는 권한 부여
     */
    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(@Qualifier("oauthJdbcTemplate") JdbcTemplate oauthJdbcTemplate,
                                                                         RegisteredClientRepository clientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(oauthJdbcTemplate, clientRepository);
    }

    /**
     * @from authorization_code, client_credentials, refresh_token
     * code -> OAuth2AuthorizationCode
     * access_token -> OAuth2AccessToken
     * refresh_token -> OAuth2RefreshToken
     * id_token -> OidcIdToken
     */
    @Bean
    public OAuth2TokenGenerator<?> tokenGenerator(JwtEncoder jwtEncoder) {
        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
        return new DelegatingOAuth2TokenGenerator(
                jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
    }

    /**
     * OpenID Connect 1.0이 활성화된 경우 SessionRegistry 인스턴스가 인증된 세션을 추적하는 데 사용
     */
    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    /**
     * 라이언트 인증, 권한 부여 처리, 토큰 검사, 동적 클라이언트 등록 등 특정 프로토콜 흐름을 따를 때 다른 구성 요소에서 사용
     */
    /*@Bean
    public RegisteredClientRepository registeredClientRepository(@Qualifier("oauthJdbcTemplate") JdbcTemplate jdbcTemplate) {
        return new JdbcRegisteredClientRepository(jdbcTemplate);
    }*/
    @Bean
    public RegisteredClientRepository registeredClientRepository(@Qualifier("oauthJdbcTemplate") JdbcTemplate jdbcTemplate) {
        JdbcRegisteredClientRepository jdbcRegisteredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);

        ObjectMapper objectMapper = this.securityObjectMapper();

        // Mapper 적용
        JdbcRegisteredClientRepository.RegisteredClientRowMapper rowMapper =
                new JdbcRegisteredClientRepository.RegisteredClientRowMapper();
        rowMapper.setObjectMapper(objectMapper);

        JdbcRegisteredClientRepository.RegisteredClientParametersMapper parametersMapper =
                new JdbcRegisteredClientRepository.RegisteredClientParametersMapper();
        parametersMapper.setObjectMapper(objectMapper);

        jdbcRegisteredClientRepository.setRegisteredClientRowMapper(rowMapper);
        jdbcRegisteredClientRepository.setRegisteredClientParametersMapper(parametersMapper);

        return jdbcRegisteredClientRepository;
    }


    /**
     * 새로운 권한이 저장되고 기존 권한이 쿼리
     * OidcScopes.OPENID
     */
    /*@Bean
    public OAuth2AuthorizationService authorizationService(@Qualifier("oauthJdbcTemplate") JdbcTemplate jdbcTemplate,
                                                           RegisteredClientRepository clientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, clientRepository);
    }*/
    @Bean
    public OAuth2AuthorizationService authorizationService(@Qualifier("oauthJdbcTemplate") JdbcTemplate jdbcTemplate,
                                                           RegisteredClientRepository registeredClientRepository) {

        JdbcOAuth2AuthorizationService authorizationService =
                new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);

        ObjectMapper objectMapper = this.securityObjectMapper();

        // Mapper 적용
        JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper rowMapper =
                new JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper(registeredClientRepository);
        rowMapper.setObjectMapper(objectMapper);

        JdbcOAuth2AuthorizationService.OAuth2AuthorizationParametersMapper parametersMapper =
                new JdbcOAuth2AuthorizationService.OAuth2AuthorizationParametersMapper();
        parametersMapper.setObjectMapper(objectMapper);

        authorizationService.setAuthorizationRowMapper(rowMapper);
        authorizationService.setAuthorizationParametersMapper(parametersMapper);

        return authorizationService;
    }

    private ObjectMapper securityObjectMapper() {
        // ObjectMapper 커스터마이징
        ObjectMapper objectMapper = new ObjectMapper();

        // Spring Security 관련 모듈 등록
        ClassLoader classLoader = JdbcOAuth2AuthorizationService.class.getClassLoader();
        List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
        objectMapper.registerModules(securityModules);
        objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());

        // Boolean, String, etc. 허용할 Mixin 추가
        objectMapper.addMixIn(Boolean.class, SynchronizedSetMixin.class);
        objectMapper.addMixIn(String.class, SynchronizedSetMixin.class);
        objectMapper.addMixIn(Integer.class, SynchronizedSetMixin.class);
        objectMapper.addMixIn(Long.class, SynchronizedSetMixin.class);
        objectMapper.addMixIn(CustomUserDetails.class, SynchronizedSetMixin.class);
        objectMapper.addMixIn(Collections.synchronizedSet(new HashSet<>()).getClass(), SynchronizedSetMixin.class);

        /*// 보안상 위험함, 운영에서는 지양
        objectMapper.activateDefaultTyping(
                LaissezFaireSubTypeValidator.instance,
                ObjectMapper.DefaultTyping.NON_FINAL,
                JsonTypeInfo.As.PROPERTY
        );*/

        return objectMapper;
    }
}

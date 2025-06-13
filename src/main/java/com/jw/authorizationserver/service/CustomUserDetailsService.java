package com.jw.authorizationserver.service;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Service
public class CustomUserDetailsService implements org.springframework.security.core.userdetails.UserDetailsService {

    private final JdbcTemplate resourceJdbcTemplate;

    public CustomUserDetailsService(@Qualifier("resourceJdbcTemplate") JdbcTemplate resourceJdbcTemplate) {
        this.resourceJdbcTemplate = resourceJdbcTemplate;
    }

    @Override
    public UserDetails loadUserByUsername(String userId) throws UsernameNotFoundException {
        try {
            String sql = "  SELECT  user_id, " +
                    "               password, " +
                    "               enabled, " +
                    "               account_non_expired, " +
                    "               credentials_non_expired," +
                    "               account_non_locked," +
                    "               created_at," +
                    "               updated_at," +
                    "               email," +
                    "               phone " +
                    "       FROM    resource.dbo.users " +
                    "       WHERE   user_id = ?";

            return this.resourceJdbcTemplate.queryForObject(sql, (rs, rowNum) -> {
                String user_id = rs.getString("user_id");
                String password = rs.getString("password");
                boolean enabled = rs.getBoolean("enabled");
                boolean account_non_expired = rs.getBoolean("account_non_expired");
                boolean credentials_non_expired = rs.getBoolean("credentials_non_expired");
                boolean account_non_locked = rs.getBoolean("account_non_locked");
                LocalDateTime created_at = rs.getObject("created_at", LocalDateTime.class);
                LocalDateTime updated_at = rs.getObject("updated_at", LocalDateTime.class);
                String email = rs.getString("email");
                String phone = rs.getString("phone");

                List<GrantedAuthority> authorities = Stream.of("ROLE_USER").map(SimpleGrantedAuthority::new).collect(Collectors.toList());

                return new CustomUserDetails(
                        user_id,
                        password,
                        enabled,
                        account_non_expired,
                        credentials_non_expired,
                        account_non_locked,
                        authorities,
                        created_at,
                        updated_at,
                        email,
                        phone);
                /*See https://github.com/spring-projects/spring-security/issues/4370 for details*/
                /*return new org.springframework.security.core.userdetails.User(
                        user_id,
                        password,
                        enabled,
                        account_non_expired,
                        credentials_non_expired,
                        account_non_locked,
                        authorities
                );*/
            }, userId);

        } catch (EmptyResultDataAccessException e) {
            throw new UsernameNotFoundException("User not found");
        }
    }
}

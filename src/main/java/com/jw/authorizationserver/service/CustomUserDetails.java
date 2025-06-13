package com.jw.authorizationserver.service;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.time.LocalDateTime;
import java.util.Collection;

@Getter
public class CustomUserDetails extends User {

    private final LocalDateTime createdAt;
    private final LocalDateTime updatedAt;
    private final String email;
    private final String phone;

    public CustomUserDetails(final String username,
                             final String password,
                             final boolean enabled,
                             final boolean accountNonExpired,
                             final boolean credentialsNonExpired,
                             final boolean accountNonLocked, Collection<? extends GrantedAuthority> authorities,
                             final LocalDateTime createdAt,
                             final LocalDateTime updatedAt,
                             final String email,
                             final String phone) {
        super(username, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
        this.email = email;
        this.phone = phone;
    }
}

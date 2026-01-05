package com.jw.authorizationserver.config.userdetails;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements org.springframework.security.core.userdetails.UserDetailsService {

    private final UserDetailsRepository repository;

    public CustomUserDetailsService(final UserDetailsRepository repository) {
        this.repository = repository;
    }

    @Override
    public UserDetails loadUserByUsername(String username)
            throws UsernameNotFoundException {

        UserWithRoles user = this.repository.findUserWithRoles(username)
                .orElseThrow(() ->
                        new UsernameNotFoundException("User not found: " + username)
                );

        return org.springframework.security.core.userdetails.User.builder()
                .username(user.userId())
                .password(user.password())
                .authorities(
                        user.roles().stream()
                                .map(role -> "ROLE_" + role)
                                .map(SimpleGrantedAuthority::new)
                                .toList()
                )
                .accountExpired(!user.accountNonExpired())
                .accountLocked(!user.accountNonLocked())
                .credentialsExpired(!user.credentialsNonExpired())
                .disabled(!user.enabled())
                .build();
    }
}

package com.jw.authorizationserver.config.userdetails;

import java.util.List;

public record UserWithRoles(
        String userId,
        String password,
        boolean enabled,
        boolean accountNonExpired,
        boolean credentialsNonExpired,
        boolean accountNonLocked,
        List<String> roles
) {}

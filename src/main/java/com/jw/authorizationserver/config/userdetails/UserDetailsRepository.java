package com.jw.authorizationserver.config.userdetails;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Repository
public class UserDetailsRepository {

    private final JdbcTemplate oauthJdbcTemplate;

    public UserDetailsRepository(@Qualifier("oauthJdbcTemplate") JdbcTemplate oauthJdbcTemplate) {
        this.oauthJdbcTemplate = oauthJdbcTemplate;
    }

    public Optional<UserWithRoles> findUserWithRoles(String userId) {

        String sql = """
                    SELECT      A.user_id                   AS user_id,
                                A.password                  AS password,
                                A.enabled                   AS enabled,
                                A.account_non_expired       AS account_non_expired,
                                A.credentials_non_expired   AS credentials_non_expired,
                                A.account_non_locked        AS account_non_locked,
                                C.role_name                 AS role_name
                    FROM        oauth.dbo.user_details    AS A
                    LEFT JOIN   oauth.dbo.user_roles      AS B ON A.user_id = B.user_id
                    LEFT JOIN   oauth.dbo.roles           AS C ON B.role_id = C.role_id
                    WHERE       A.user_id = ?
                """;

        return this.oauthJdbcTemplate.query(sql, rs -> {
            if (!rs.next()) return Optional.empty();

            List<String> roles = new ArrayList<>();
            String id = rs.getString("user_id");
            String pw = rs.getString("password");

            boolean enabled = rs.getBoolean("enabled");
            boolean accountNonExpired = rs.getBoolean("account_non_expired");
            boolean credentialsNonExpired = rs.getBoolean("credentials_non_expired");
            boolean accountNonLocked = rs.getBoolean("account_non_locked");

            do {
                String role = rs.getString("role_name");
                if (role != null) roles.add(role);
            } while (rs.next());

            return Optional.of(
                    new UserWithRoles(
                            id, pw, enabled,
                            accountNonExpired,
                            credentialsNonExpired,
                            accountNonLocked,
                            roles
                    )
            );
        }, userId);
    }
}

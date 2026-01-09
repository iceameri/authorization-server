package com.jw.authorizationserver.config.jdbc;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.core.JdbcTemplate;

import javax.sql.DataSource;


@Configuration
public class DataSourceConfig {

    @Primary
    @Bean(name = "oauthDataSource")
    @ConfigurationProperties(prefix = "spring.datasource")
    public DataSource oauthDataSource() {
        return DataSourceBuilder.create().build();
    }

    @Bean(name = "oauthJdbcTemplate")
    public JdbcTemplate oauthJdbcTemplate(@Qualifier("oauthDataSource") DataSource dataSource) {
        return new JdbcTemplate(dataSource);
    }

    @Bean(name = "resourceDataSource")
    @ConfigurationProperties(prefix = "spring.secondary-datasource")
    public javax.sql.DataSource serviceDataSource() {
        return DataSourceBuilder.create().build();
    }

    @Bean(name = "resourceJdbcTemplate")
    public JdbcTemplate resourceJdbcTemplate(@Qualifier("resourceDataSource") DataSource dataSource) {
        return new JdbcTemplate(dataSource);
    }
}

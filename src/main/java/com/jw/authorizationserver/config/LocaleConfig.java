package com.jw.authorizationserver.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.i18n.FixedLocaleResolver;

import java.util.Locale;

@Configuration
public class LocaleConfig {
    @Value("${app.locale.language}")
    private String language;

    @Value("${app.locale.country}")
    private String country;

    @Bean
    public LocaleResolver localeResolver() {
        return new FixedLocaleResolver(new Locale(this.language, this.country));
    }
}

package com.shudong.spring.authorizationserverpassword

import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter


@Configuration
@EnableResourceServer
class OAuth2ResourceServer : ResourceServerConfigurerAdapter() {
    @Throws(Exception::class)
    override fun configure(http: HttpSecurity) {
        http
            .authorizeRequests()
            .antMatchers("/api/**").authenticated()
            .antMatchers("/").permitAll()
    }
}
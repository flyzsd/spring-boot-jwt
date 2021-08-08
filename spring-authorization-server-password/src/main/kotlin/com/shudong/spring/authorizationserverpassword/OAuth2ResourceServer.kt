package com.shudong.spring.authorizationserverpassword

import org.springframework.context.annotation.Configuration
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer

//it seems there is some conflict between form login (required for authorization code flow) and resource server. We can only choose one.
//so it is best to not configure the same project as resource server
@Configuration
@EnableResourceServer
class OAuth2ResourceServer : ResourceServerConfigurerAdapter() {

    override fun configure(resources: ResourceServerSecurityConfigurer) {
        resources.resourceId("api")
    }
}
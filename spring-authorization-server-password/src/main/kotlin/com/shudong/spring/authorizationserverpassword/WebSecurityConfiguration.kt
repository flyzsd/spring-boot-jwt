package com.shudong.spring.authorizationserverpassword

import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Primary
import org.springframework.core.io.Resource
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.provider.token.DefaultTokenServices
import org.springframework.security.oauth2.provider.token.TokenStore
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory
import org.springframework.security.provisioning.InMemoryUserDetailsManager


@EnableWebSecurity
class WebSecurityConfiguration : WebSecurityConfigurerAdapter() {
    @Throws(Exception::class)
    override fun configure(http: HttpSecurity) {
        http
            .requestMatchers().antMatchers("/login", "/oauth/authorize")
            .and()
            .authorizeRequests().anyRequest().authenticated()
            .and()
            .formLogin().permitAll()
    }

//    @Throws(Exception::class)
//    override fun configure(http: HttpSecurity) {
//        http
//            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//            .and()
//            .httpBasic()
//            .realmName("JWT")
//            .and()
//            .csrf()
//            .disable()
//    }

    @Bean
    fun passwordEncoder(): PasswordEncoder {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder()
    }

    @Bean
    fun UserDetailsService(): UserDetailsService {
        val u1 = User.withUsername("admin").password(passwordEncoder().encode("admin")).roles("ADMIN").authorities("read", "write").build()
        val u2 = User.withUsername("user").password(passwordEncoder().encode("user")).roles("USER").authorities("read").build()
        return InMemoryUserDetailsManager(u1, u2)
    }

    @Bean
    @Throws(Exception::class)
    override fun authenticationManagerBean(): AuthenticationManager {
        return super.authenticationManagerBean()
    }

    @Bean
    fun tokenStore(jwtAccessTokenConverter: JwtAccessTokenConverter?): TokenStore {
        return JwtTokenStore(jwtAccessTokenConverter)
    }

    @Bean
    @Primary //Making this primary to avoid any accidental duplication with another token service instance of the same name
    fun tokenServices(tokenStore: TokenStore?): DefaultTokenServices {
        val defaultTokenServices = DefaultTokenServices()
        defaultTokenServices.setTokenStore(tokenStore)
        defaultTokenServices.setSupportRefreshToken(true)
        return defaultTokenServices
    }

    @Bean
    fun accessTokenConverter(@Value("classpath:mytest.jks") keyFile: Resource): JwtAccessTokenConverter {
        val converter = JwtAccessTokenConverter()
        val keyStoreKeyFactory = KeyStoreKeyFactory(keyFile, "mypass".toCharArray())
        converter.setKeyPair(keyStoreKeyFactory.getKeyPair("mytest"))
        return converter
    }
}
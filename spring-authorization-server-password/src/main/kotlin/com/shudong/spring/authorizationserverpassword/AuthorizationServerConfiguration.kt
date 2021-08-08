package com.shudong.spring.authorizationserverpassword

import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken
import org.springframework.security.oauth2.common.OAuth2AccessToken
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.security.oauth2.provider.token.TokenEnhancer
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain
import org.springframework.security.oauth2.provider.token.TokenStore
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter

class CustomTokenEnhancer : TokenEnhancer {
    override fun enhance(accessToken: OAuth2AccessToken, authentication: OAuth2Authentication): OAuth2AccessToken {
        val additionalInfo = HashMap<String, Any>()
        additionalInfo["organization"] = authentication.name + "randomAlphabetic(4)"
        (accessToken as DefaultOAuth2AccessToken).additionalInformation = additionalInfo
        return accessToken
    }
}

@Configuration
@EnableAuthorizationServer
class AuthorizationServerConfiguration(
    private val jwtAccessTokenConverter: JwtAccessTokenConverter,
    private val tokenStore: TokenStore,
    private val passwordEncoder: PasswordEncoder,
    private val authenticationManager: AuthenticationManager
) : AuthorizationServerConfigurerAdapter() {
    override fun configure(endpoints: AuthorizationServerEndpointsConfigurer) {
        val tokenEnhancerChain = TokenEnhancerChain()
        tokenEnhancerChain.setTokenEnhancers(
            listOf(
                CustomTokenEnhancer(),
                jwtAccessTokenConverter
            )
        )
        endpoints
            .tokenStore(tokenStore)
            .reuseRefreshTokens(false)
            .tokenEnhancer(tokenEnhancerChain)
            .authenticationManager(authenticationManager)
    }

    @Throws(Exception::class)
    override fun configure(clients: ClientDetailsServiceConfigurer) {
        clients
            .inMemory()
            .withClient("client")
            .secret(passwordEncoder.encode("secret"))
            .authorizedGrantTypes("password", "refresh_token", "client_credentials")
            .scopes("read", "write")
    }

    @Throws(Exception::class)
    override fun configure(oauthServer: AuthorizationServerSecurityConfigurer) {
        oauthServer
            .tokenKeyAccess("hasAuthority('read')")
            .checkTokenAccess("hasAuthority('read')")
    }
}
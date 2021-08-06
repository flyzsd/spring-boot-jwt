package com.shudong.spring.resourceserver.controller

import org.slf4j.LoggerFactory
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

private val logger = LoggerFactory.getLogger(HelloController::class.java)

@RestController
class HelloController {

    @GetMapping(".well-known/jwks.json")
    fun getJwkSet(): String {
        return "{ \"keys\": [ { \"kty\": \"RSA\", \"e\": \"AQAB\", \"n\": \"jvBtqsGCOmnYzwe_-HvgOqlKk6HPiLEzS6uCCcnVkFXrhnkPMZ-uQXTR0u-7ZklF0XC7-AMW8FQDOJS1T7IyJpCyeU4lS8RIf_Z8RX51gPGnQWkRvNw61RfiSuSA45LR5NrFTAAGoXUca_lZnbqnl0td-6hBDVeHYkkpAsSck1NPhlcsn-Pvc2Vleui_Iy1U2mzZCM1Vx6Dy7x9IeP_rTNtDhULDMFbB_JYs-Dg6Zd5Ounb3mP57tBGhLYN7zJkN1AAaBYkElsc4GUsGsUWKqgteQSXZorpf6HdSJsQMZBDd7xG8zDDJ28hGjJSgWBndRGSzQEYU09Xbtzk-8khPuw\" } ] }"
    }

    @GetMapping("hello")
    fun hello(@AuthenticationPrincipal jwt: Jwt): String {
        logger.info("hello {}", jwt.subject)
        return String.format("Hello, %s!", jwt.subject)
    }

    @GetMapping("hello2")
    fun hello2(authToken: JwtAuthenticationToken): String {
        logger.info("hello2 {}", authToken.token.subject)
        return String.format("Hello, %s!", authToken.token.subject)
    }

}
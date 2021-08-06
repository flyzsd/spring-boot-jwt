package com.shudong.spring.resourceserver

import com.nimbusds.jose.util.Base64
import org.junit.jupiter.api.Test
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.RSAPublicKeySpec


class GeneratePublicKeyTest {
    @Test
    fun test() {
        val n = Base64("jvBtqsGCOmnYzwe_-HvgOqlKk6HPiLEzS6uCCcnVkFXrhnkPMZ-uQXTR0u-7ZklF0XC7-AMW8FQDOJS1T7IyJpCyeU4lS8RIf_Z8RX51gPGnQWkRvNw61RfiSuSA45LR5NrFTAAGoXUca_lZnbqnl0td-6hBDVeHYkkpAsSck1NPhlcsn-Pvc2Vleui_Iy1U2mzZCM1Vx6Dy7x9IeP_rTNtDhULDMFbB_JYs-Dg6Zd5Ounb3mP57tBGhLYN7zJkN1AAaBYkElsc4GUsGsUWKqgteQSXZorpf6HdSJsQMZBDd7xG8zDDJ28hGjJSgWBndRGSzQEYU09Xbtzk-8khPuw").decodeToBigInteger()
        val e = Base64("AQAB").decodeToBigInteger()
        val factory: KeyFactory = KeyFactory.getInstance("RSA")
        val pubKey: PublicKey = factory.generatePublic(RSAPublicKeySpec(n, e))
        val base64encoded: String = Base64.encode(pubKey.encoded).toString()
        println(base64encoded)
    }
}
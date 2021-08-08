package com.shudong.spring.authorizationserver

import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api")
class HelloController {

    @GetMapping("/hello")
    fun hello(): String {
        println("hello")
        val user = SecurityContextHolder.getContext().authentication.principal
        println("user = $user")
        return "hello"
    }

}
package com.shudong.spring.authorizationserverpassword.controller

import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController


@RequestMapping("/api")
@RestController
class HelloController {

    @GetMapping("/hello")
    fun hello(): String {
        println("from hello")
        val user = SecurityContextHolder.getContext().authentication.principal
        println("user = $user")
        return "hello"
    }
}
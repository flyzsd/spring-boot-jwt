package com.shudong.spring.authorizationserverpassword.controller

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RequestMapping("/api")
@RestController
class HelloController {

    @GetMapping("/hello")
    fun hello(): String {
        println("from hello")
        return "hello"
    }
}
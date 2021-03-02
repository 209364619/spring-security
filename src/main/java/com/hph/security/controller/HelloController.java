package com.hph.security.controller;

import com.hph.security.service.AnnotationSecurityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {
    @Autowired
    AnnotationSecurityService annotationSecurityService;

    @GetMapping("/hello")
    public String hello(){
        return "Hello Spring Security!";
    }

    @GetMapping("/admin")
    public String admin(){
        return "hello admin";
    }

    @GetMapping("/db")
    public String db(){
        return "hello dba";
    }

    @GetMapping("/user")
    public String user(){
        return "user";
    }

    @GetMapping("/super_admin")
    public String superUser(){
        return annotationSecurityService.superUser();
    }

    @GetMapping("/visitor")
    public String visitor(){
        return annotationSecurityService.visitor();
    }
}

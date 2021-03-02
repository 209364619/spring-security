package com.hph.security.service;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

/**
 * 通过注解限定用户
 */
@Service
public class AnnotationSecurityService {

    @Secured("SUPER_ADMIN")
    public String superUser(){
        return "SuperUser";
    }

    @PreAuthorize("hasAnyRole('USER','VISITOR','SUPER_ADMIN','DBA')")
    public String visitor(){
        return "hasAnyRole('USER','VISITOR','SUPER_ADMIN','DBA')";
    }

}

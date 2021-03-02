package com.hph.security.service;

import com.hph.security.entity.Role;
import com.hph.security.mapper.UserMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class UserServiceTest {
    @Autowired
    UserService userService;

    @Test
    public void getUserRole(){
        Integer id = 1;
        List<Role> userRolesByUserId = userService.getUserRolesByUserId(id);
        for (Role role : userRolesByUserId) {
            System.out.println(role.getNamezh());
        }
    }
}
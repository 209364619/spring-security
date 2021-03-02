package com.hph.security.mapper;

import com.hph.security.entity.Role;
import com.hph.security.entity.User;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

@Mapper
public interface UserMapper {
    User loadUserByUsername(String username);
    List<Role> getUserRolesByUserId(Integer id);
}

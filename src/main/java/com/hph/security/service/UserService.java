package com.hph.security.service;

import com.hph.security.entity.Role;
import com.hph.security.entity.User;
import com.hph.security.mapper.UserMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService implements UserDetailsService {
    @Autowired
    UserMapper userMapper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userMapper.loadUserByUsername(username);
        if (user == null){
            throw new UsernameNotFoundException("账户不存在！");
        }else {
            user.setRoles(userMapper.getUserRolesByUserId(user.getId()));
            return user;
        }
    }

    public List<Role> getUserRolesByUserId(Integer id){
        List<Role> userRolesByUserId = userMapper.getUserRolesByUserId(id);
        return userRolesByUserId;
    }
}

package com.hph.security.conf;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.hph.security.entity.User;
import com.hph.security.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true) //开启基于注解的鉴权方式
public class MyWebSecurityConfiguration extends WebSecurityConfigurerAdapter {
    @Autowired
    UserService userService;

    @Bean
    PasswordEncoder passwordEncoder(){
        return NoOpPasswordEncoder.getInstance();
    }

    /**
     * 基于内存的用户认证
     * 配置用户名密码用户角色
     * @param auth
     * @throws Exception
     */
    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("root").password("123456").roles("ADMIN", "DBA")
                .and()
                .withUser("admin").password("123456").roles("ADMIN", "USER")
                .and()
                .withUser("hph").password("123456").roles("USER")
                .and()
                .withUser("super_admin").password("123456").roles("SUPER_ADMIN")
                .and()
                .withUser("visitor").password("123456").roles("VISITOR");
        auth.userDetailsService(userService); //启用基于数据库的登录
    }

    /**
     * 配置访问页面URL与权限关系
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/admin/**")
                .hasRole("ADMIN")
                .antMatchers("/user/**")
                .access("hasAnyRole('ADMIN','USER')")
                .antMatchers("/db/**")
                .access("hasRole('ADMIN') and hasRole('DBA')")
                .anyRequest() //除了上述页面外的页面，其他页面需要登录认证后才能使用
                .authenticated()
                .and()
                .formLogin()
                .loginProcessingUrl("/login")
                .usernameParameter("name")
                .passwordParameter("passwd")
                .successHandler(new AuthenticationSuccessHandler() { //登录成功处理, 前后端分离，将结果修改为json相应
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
                        Object principal = authentication.getPrincipal();
                        httpServletResponse.setContentType("application/json;charset=utf-8");
                        PrintWriter writer = httpServletResponse.getWriter();

                        //实现UserDetail接口后返回数据中passwd字段设置为null
                        if (principal instanceof User){
                            ((User) principal).setPassword(null);
                        }
                        Map<String, Object> map = new HashMap<>();
                        map.put("status", HttpStatus.OK.value());
                        map.put("msg", principal);
                        ObjectMapper objectMapper = new ObjectMapper();
                        writer.write(objectMapper.writeValueAsString(map));

                        writer.flush();
                        writer.close();

                    }
                })
                .failureHandler(new AuthenticationFailureHandler() { //登录失败处理
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
                        httpServletResponse.setContentType("applicaiton/json;charset=utf-8");
                        PrintWriter writer = httpServletResponse.getWriter();
                        Map<String, Object> resultMap = new HashMap<>();
                        httpServletResponse.setStatus(HttpStatus.UNAUTHORIZED.value());
                        resultMap.put("status", HttpStatus.UNAUTHORIZED.value());
                        resultMap.put("msg", e.getMessage());

                        ObjectMapper om = new ObjectMapper();
                        writer.write(om.writeValueAsString(resultMap));
                        writer.flush();
                        writer.close();
                    }
                })
                .permitAll() //login接口不需要认证即可访问
                .and()
                .logout()
                .logoutUrl("/logout") //配置注销登录
                .clearAuthentication(true)
                .invalidateHttpSession(true)
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) {
                        try {
                            httpServletResponse.sendRedirect("/login_page");
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }
                })
                .and()
                .csrf()//关闭csrf
                .disable();
    }


}

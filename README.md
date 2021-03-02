# spring boot Security
## 基于内存的用户鉴权登录

```java
//通过编码实现用户名密码
@Configuration
public class MyWebSecurityConfiguration extends WebSecurityConfigurerAdapter {
    @Bean
    PasswordEncoder passwordEncoder(){
        return NoOpPasswordEncoder.getInstance();
    }
    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("root").password("123456").roles("ADMIN", "DBA");
    }
}
```
## 基于注解的权限登录
```java
//WebSecurityConfigurerAdapter 实现方法上添加该注解
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true) //开启基于注解的鉴权方式
```
## 前后端分离，修改登录返回值
> configure重写过程中添加：
```java
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
```
## 结合mysql，使用数据库用户名密码登录
- spring数据源配置
- mybatis引入
- 配置*mapper.xml路径
- 实现UserDetails接口
- 实现UserDetailsService接口
- WebSecurityConfigurerAdapter实现接口-configure方法中启用auth.userDetailsService(userService);

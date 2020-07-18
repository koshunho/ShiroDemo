# ShiroDemo

#### 数据库字段
```sql
CREATE TABLE `user` (
  `id` INT(32) NOT NULL AUTO_INCREMENT,
  `username` VARCHAR(255) NOT NULL,
  `password` VARCHAR(255) NOT NULL,
  `role` VARCHAR(255) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
```
#### 配置UserRealm

在Controller封装了token，这个token就是全局的。

此处 盐 = 用户名
```java
public class UserRealm extends AuthorizingRealm {

    @Autowired
    UserService userService;

    //授权
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {

        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();

        //拿到当前登录的对象
        Subject subject = SecurityUtils.getSubject();

        //这里就是从AuthenticationInfo取到当前的对象principal
        // 因为把user作为第一个参数传递过来了
        User currentUser = (User) subject.getPrincipal(); //拿到user对象

        //设置当前用户的权限
        HashSet<String> set = new HashSet<>();
        set.add(currentUser.getRole());
        info.setRoles(set);

        //return info
        return info;
    }

    //认证
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        System.out.println("执行了认证方法");

        //这些类是有联系的，controller里面封装了token，就是一个全局的，都可以调得到
        UsernamePasswordToken userToken = (UsernamePasswordToken) token;

        //在执行登录的时候，就会走到这个方法
        //用户名 密码 从数据库中取
        User user = userService.queryUserByName(userToken.getUsername());

        if(user == null){
            // 抛出异常 UnknownAccountException
            return null;
        }

        Object principal = user;

        Object credentials = user.getPassword();

        ByteSource salt = ByteSource.Util.bytes(user.getUsername());

        String realmName = getName();

        //密码认证，shiro做
        return new SimpleAuthenticationInfo(principal,credentials,salt,realmName);
    }
}
```

#### 配置ShiroConfig
Shiro的内置过滤器，必须按照顺序写。`filterMap.put("/**","authc")`拦截所有请求，一定是放在最后的
```java
@Configuration
public class ShiroConfig {
    //ShiroFilterFactoryBean
    @Bean
    public ShiroFilterFactoryBean shiroFilterFactoryBean(@Qualifier("defaultWebSecurityManager") DefaultWebSecurityManager defaultWebSecurityManager){
        ShiroFilterFactoryBean bean = new ShiroFilterFactoryBean();

        bean.setSecurityManager(defaultWebSecurityManager);

        //添加shiro的内置过滤器
        /*anon:无须认证就可以访问
        * authc：必须认证了才能访问
        * user：必须拥有 记住我 功能才能使用
        * perms：拥有对某个资源的权限才能访问
        * role：拥有某个角色权限才能访问*/
        LinkedHashMap<String, String> filterMap = new LinkedHashMap<>();

        filterMap.put("/","anon");
        filterMap.put("/index","anon");
        filterMap.put("/login","anon");
        filterMap.put("/toLogin","anon");
        filterMap.put("/toRegister","anon");
        filterMap.put("/doRegister","anon");


        filterMap.put("/user/add","roles[admin]");
        filterMap.put("/user/update","roles[user]");

        filterMap.put("/logout","logout");

        filterMap.put("/**","authc");

        bean.setFilterChainDefinitionMap(filterMap);

        //设置登录的请求
        bean.setLoginUrl("/toLogin");

        bean.setUnauthorizedUrl("/notRole");

        return bean;
    }

    //DefaultWebSecurityManager
    @Bean
    public DefaultWebSecurityManager defaultWebSecurityManager(@Qualifier("userRealm") UserRealm userRealm){
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();

        securityManager.setRealm(userRealm);

        return securityManager;
    }

    //创建realm对象，需要自定义类
    @Bean
    public UserRealm userRealm(@Qualifier("hashedCredentialsMatcher") HashedCredentialsMatcher matcher){
        UserRealm userRealm = new UserRealm();

        userRealm.setAuthorizationCachingEnabled(false);

        userRealm.setCredentialsMatcher(matcher);

        return userRealm;
    }

    //密码匹配凭证管理器
    @Bean
    public HashedCredentialsMatcher hashedCredentialsMatcher() {
        HashedCredentialsMatcher hashedCredentialsMatcher = new HashedCredentialsMatcher();
        // 采用MD5方式加密
        hashedCredentialsMatcher.setHashAlgorithmName("MD5");
        // 设置加密次数
        hashedCredentialsMatcher.setHashIterations(1024);
        // true加密用的hex编码，false用的base64编码
        hashedCredentialsMatcher.setStoredCredentialsHexEncoded(true);

        return hashedCredentialsMatcher;
    }
}
```

#### 实现登录
```java
    @RequestMapping("/login")
    public String login(@RequestParam(value = "username") String username,
                        @RequestParam(value = "password") String pwd,
                        Model model, HttpSession session){
        //获取当前的用户
        Subject subject = SecurityUtils.getSubject();

        //封装用户的登录数据
        UsernamePasswordToken token = new UsernamePasswordToken(username, pwd);

        try {
            //执行登录方法，如果没有异常就OK
            subject.login(token);
            session.setAttribute("loginUser",username);
            return "redirect:/index";
        }catch (UnknownAccountException e){
            model.addAttribute("msg","用户名不存在");
            return "login";
        }catch(IncorrectCredentialsException e){
            model.addAttribute("msg","密码错误");
            return "login";
        }
    }
```

#### 实现注册

注意：
1. 前面HashedCredentialsMatcher用的Hex编码，所以这里也需要Hex编码
2. 得出加密结果后，就替换掉user原来的密码 

```java
    @Override
    public int registerUser(User user) {
        ByteSource salt = ByteSource.Util.bytes(user.getUsername());

        String md5 = new SimpleHash("MD5", user.getPassword(), salt, 1024).toHex();

        user.setPassword(md5);

        User temp = userMapper.queryUserByName(user.getUsername());

        if(temp == null){
            userMapper.registerUser(user);
            return 1;
        }

        return 0;
    }
```

#### 测试
![首页](http://qcorkht4q.bkt.clouddn.com/blog1595079824240.png)

目标是role为admin，只能进入add；role为user，只能进入update

---

如果是登录状态，就会显示 当前用户为：xxx

未登录状态点击add/update，就会被拦截，进入登录页面
![登录页面](http://qcorkht4q.bkt.clouddn.com/blog1595079966049.png)

数据库中没有该用户名，就显示
![用户名不存在](http://qcorkht4q.bkt.clouddn.com/blog1595080067624.png)

密码不正确，显示
![密码错误](http://qcorkht4q.bkt.clouddn.com/blog1595080096218.png)

---

fukuoka是一个role = admin的user
![fukuoka](http://qcorkht4q.bkt.clouddn.com/blog1595080164672.png)
![add](http://qcorkht4q.bkt.clouddn.com/blog1595080178908.png)
点update，就会跳转到没有权限页面
![没有权限](http://qcorkht4q.bkt.clouddn.com/blog1595080222493.png)

---
![注册](http://qcorkht4q.bkt.clouddn.com/blog1595080242682.png)

username: okinawa
password: okinawa
![okinawa](http://qcorkht4q.bkt.clouddn.com/blog1595080408820.png)

数据库中的密码就是MD5加密后的
![MD5](http://qcorkht4q.bkt.clouddn.com/blog1595080443855.png)
package com.huang.config;

import com.huang.pojo.User;
import com.huang.service.UserService;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ByteSource;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.HashSet;

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

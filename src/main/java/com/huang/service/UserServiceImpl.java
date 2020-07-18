package com.huang.service;

import com.huang.mapper.UserMapper;
import com.huang.pojo.User;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.util.ByteSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UserServiceImpl implements UserService{

    @Autowired
    UserMapper userMapper;

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

    @Override
    public User queryUserByName(String name) {
        return userMapper.queryUserByName(name);
    }
}

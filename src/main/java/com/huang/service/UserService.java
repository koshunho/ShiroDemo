package com.huang.service;

import com.huang.pojo.User;

public interface UserService {
    User queryUserByName(String name);

    int registerUser(User user);
}


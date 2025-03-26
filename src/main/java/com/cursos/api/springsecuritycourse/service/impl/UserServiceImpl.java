package com.cursos.api.springsecuritycourse.service.impl;
import com.cursos.api.springsecuritycourse.dto.SaveUser;
import com.cursos.api.springsecuritycourse.exception.InvalidPasswordException;
import com.cursos.api.springsecuritycourse.exception.ObjectNotFoundException;
import com.cursos.api.springsecuritycourse.persistence.entity.security.Role;
import com.cursos.api.springsecuritycourse.persistence.entity.security.User;
import com.cursos.api.springsecuritycourse.persistence.repository.security.UserRepository;
import com.cursos.api.springsecuritycourse.service.RoleService;
import com.cursos.api.springsecuritycourse.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.Optional;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;


    @Autowired
    private RoleService roleService;

    @Override
    public User registerOneCustomer(SaveUser newUser) {
        validatePassword(newUser);
        User user = new User();
        user.setName(newUser.getName());
        user.setUsername(newUser.getUsername());
        user.setPassword(passwordEncoder.encode(newUser.getPassword()));
        Role defaultRole = roleService.findDefaultRole()
                        .orElseThrow(()->new ObjectNotFoundException("Role by default not Found"));
        user.setRole(defaultRole);
        return userRepository.save(user);
    }

    @Override
    public Optional<User> findOneByUsername(String user) {
        return userRepository.findByUsername(user);
    }

    private void validatePassword(SaveUser newUser) {
        if(!StringUtils.hasText(newUser.getPassword()) || !StringUtils.hasText(newUser.getRepeatedPassword())){
            throw new InvalidPasswordException("Passwords don´t match");
        }
        if(!newUser.getPassword().equals(newUser.getRepeatedPassword())){
            throw new InvalidPasswordException("Passwords don´t match");
        }
    }
}

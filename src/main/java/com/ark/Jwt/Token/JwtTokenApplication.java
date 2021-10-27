package com.ark.Jwt.Token;

import com.ark.Jwt.Token.domain.Role;
import com.ark.Jwt.Token.domain.User;
import com.ark.Jwt.Token.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class JwtTokenApplication {

    @Bean
    BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    public static void main(String[] args) {
        SpringApplication.run(JwtTokenApplication.class, args);
    }





    @Bean
    CommandLineRunner run(UserService userService) {
        return args -> {
            userService.saveRole(new Role(null, "ROLE_USER"));
            userService.saveRole(new Role(null, "ROLE_MANAGER"));
            userService.saveRole(new Role(null, "ROLE_ADMIN"));
            userService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));

            userService.saveUser(new User(null, "A1", "a1", "khan", new ArrayList<>()));
            userService.saveUser(new User(null, "A2", "a2", "khan", new ArrayList<>()));
            userService.saveUser(new User(null, "A3", "a3", "khan", new ArrayList<>()));
            userService.saveUser(new User(null, "A4", "a4", "khan", new ArrayList<>()));

            userService.addRoleToUser("A1", "ROLE_USER");
            userService.addRoleToUser("A1", "ROLE_MANAGER");
            userService.addRoleToUser("A2", "ROLE_MANAGER");
            userService.addRoleToUser("A3", "ROLE_ADMIN");
            userService.addRoleToUser("A4", "ROLE_SUPER_ADMIN");
            userService.addRoleToUser("A4", "ROLE_ADMIN");
            userService.addRoleToUser("A4", "ROLE_USER");

        };
    }

}

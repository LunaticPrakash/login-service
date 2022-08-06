package com.lunatic.loginservice.controller;

import com.lunatic.loginservice.models.AuthenticationRequest;
import com.lunatic.loginservice.models.AuthenticationResponse;
import com.lunatic.loginservice.models.User;
import com.lunatic.loginservice.service.UserService;
import com.lunatic.loginservice.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class HomeController {

    @Autowired
    JwtUtil jwtUtil;

    @Autowired
    UserService userService;

    @GetMapping("/test")
    public String test(){
        return "<h1>Test Page</>";
    }

    @GetMapping("/home")
    public String home(){
        return "<h1>Home Page</>";
    }

    @GetMapping("/user")
//    @PreAuthorize("hasRole('USER')")
    public String user(){
        return "<h1>User Page</>";
    }

    @GetMapping("/admin")
//    @PreAuthorize("hasRole('ADMIN')")
    public String admin(){
        return "<h1>Admin Page</>";
    }

    @PostMapping("/login")
    public AuthenticationResponse createJwtToken(@RequestBody AuthenticationRequest jwtRequest) throws Exception {
        return jwtUtil.createJwtToken(jwtRequest);
    }

    @PostMapping("/register")
    public User registerNewUser(@RequestBody User user) {
        return userService.registerUser(user);
    }
}

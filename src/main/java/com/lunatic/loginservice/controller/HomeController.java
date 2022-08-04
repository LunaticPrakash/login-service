package com.lunatic.loginservice.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class HomeController {

    @GetMapping("/")
    public String home(){
        return "<h1>Home Page</>";
    }

    @GetMapping("/user")
    public String user(){
        return "<h1>User Page</>";
    }

    @GetMapping("/admin")
    public String admin(){
        return "<h1>Admin Page</>";
    }
}

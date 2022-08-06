package pl.maro.newsecurity.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import static pl.maro.newsecurity.security.AuthoritiesConstants.ADMIN;

@RestController
@RequestMapping("/api/hello")
public class HelloController {

    @GetMapping("/world")
    public String helloWorld() {
        return "Hello, World!";
    }

    @GetMapping("/you")
    public String helloYou() {
        return "Hello, You!";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasAuthority(\"" + ADMIN + "\")")
    public String helloAdmin() {
        return "Hello, Admin!";
    }
}

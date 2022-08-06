package pl.maro.newsecurity.controller;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import pl.maro.newsecurity.security.Credentials;
import pl.maro.newsecurity.security.JWTToken;
import pl.maro.newsecurity.security.TokenProvider;

import javax.validation.Valid;

import static pl.maro.newsecurity.security.JWTFilter.AUTHORIZATION_HEADER;

@RestController
@RequestMapping("/api")
public class AuthenticateController {

    public static final String BEARER_PATTERN = "Bearer %s";
    private final TokenProvider tokenProvider;
    private final AuthenticationManagerBuilder authManagerBuilder;

    public AuthenticateController(TokenProvider tokenProvider, AuthenticationManagerBuilder authManagerBuilder) {
        this.tokenProvider = tokenProvider;
        this.authManagerBuilder = authManagerBuilder;
    }

    @PostMapping("/authenticate")
    public ResponseEntity<JWTToken> authorize(@Valid @RequestBody Credentials credentials) {
        var authentication = authManagerBuilder.getObject().authenticate(getToken(credentials));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        var jwt = tokenProvider.createToken(authentication);
        return new ResponseEntity<>(new JWTToken(jwt), getHttpHeaders(jwt), HttpStatus.OK);
    }

    private static UsernamePasswordAuthenticationToken getToken(Credentials credentials) {
        return new UsernamePasswordAuthenticationToken(credentials.getUsername(), credentials.getPassword());
    }

    private static HttpHeaders getHttpHeaders(String jwt) {
        var headers = new HttpHeaders();
        headers.add(AUTHORIZATION_HEADER, BEARER_PATTERN.formatted(jwt));
        return headers;
    }
}

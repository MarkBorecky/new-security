package pl.maro.newsecurity.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import io.vavr.control.Try;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;

import static io.jsonwebtoken.io.Decoders.BASE64;
import static java.util.stream.Collectors.joining;

@Component
public class TokenProvider {

    private static final Logger log = LoggerFactory.getLogger(TokenProvider.class);
    private static final String AUTHORITIES_KEY = "auth";
    private final Key key;
    private Long validTime;

    private final JwtParser jwtParser;

    public TokenProvider(
            @Value("${secret}") String secret,
            @Value("${valid-time}") Long validTime
    ) {
        this.validTime = validTime;
        key = getKey(secret);
        jwtParser = getParser(key);
    }

    private JwtParser getParser(Key key) {
        return Jwts.parserBuilder().setSigningKey(key).build();
    }

    private static SecretKey getKey(String secret) {
        var decode = BASE64.decode(secret);
        return Keys.hmacShaKeyFor(decode);
    }

    public String createToken(Authentication authentication) {
        var authorities = getAuthorities(authentication);
        var validity = new Date(new Date().getTime() + validTime);
        return Jwts.builder()
                .setSubject(authentication.getName())
                .claim(AUTHORITIES_KEY, authorities)
                .signWith(key, SignatureAlgorithm.HS256)
                .setExpiration(validity)
                .compact();
    }

    private static String getAuthorities(Authentication authentication) {
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(joining(","));
    }

    public boolean validateToken(String jwt) {
        return Try.of(() -> jwtParser.parseClaimsJws(jwt))
                .map(claimsJws -> true)
                .getOrElseGet(e -> {
                    log.error("Token validation error {}", e.getMessage());
                    return false;
                });
    }

    public Authentication getAuthentication(String token) {
        Claims claims = jwtParser.parseClaimsJws(token).getBody();

        Collection<? extends GrantedAuthority> authorities = Arrays
                .stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                .filter(auth -> !auth.trim().isEmpty())
                .map(SimpleGrantedAuthority::new)
                .toList();

        User principal = new User(claims.getSubject(), "", authorities);
        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }
}

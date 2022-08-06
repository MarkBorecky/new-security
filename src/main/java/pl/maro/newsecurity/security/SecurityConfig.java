package pl.maro.newsecurity.security;


import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.Arrays;
import java.util.Collections;

import static org.springframework.http.HttpMethod.*;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;
import static org.springframework.web.cors.CorsConfiguration.ALL;
import static pl.maro.newsecurity.security.AuthoritiesConstants.ADMIN;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class SecurityConfig {
    private final TokenProvider tokenProvider;

    public SecurityConfig(TokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedMethods(Arrays.asList(
                GET.name(),
                POST.name(),
                DELETE.name(),
                PUT.name(),
                HEAD.name(),
                POST.name(),
                OPTIONS.name()
        ));
        config.setAllowedHeaders(Collections.singletonList(ALL));
        config.setAllowedOrigins(Collections.singletonList(ALL));
        config.setMaxAge(1800L);
        source.registerCorsConfiguration("/**", config);

        return new CorsFilter(source);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .addFilterBefore(corsFilter(), UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(STATELESS)
                .and()
                .authorizeRequests()
                .antMatchers("/swagger-ui/**").permitAll()
                .antMatchers("/test/**").permitAll()
                .antMatchers("/api/authenticate").permitAll()
                .antMatchers("/api/admin/**").hasAuthority(ADMIN)
                .antMatchers("/api/hello/world").permitAll()
                .antMatchers("/api/hello/you").authenticated()
                .and()
                .httpBasic()
                .and()
                .apply(securityConfigAdapter());
        return http.build();
    }

    private JWTConfig securityConfigAdapter() {
        return new JWTConfig(tokenProvider);
    }
}

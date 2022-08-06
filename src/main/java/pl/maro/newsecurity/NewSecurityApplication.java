package pl.maro.newsecurity;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;
import pl.maro.newsecurity.domain.Authority;
import pl.maro.newsecurity.domain.User;
import pl.maro.newsecurity.repository.AuthorityRepository;
import pl.maro.newsecurity.repository.UserRepository;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

@SpringBootApplication
public class NewSecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(NewSecurityApplication.class, args);
    }

    @Bean
    public CommandLineRunner run(UserRepository userRepository, AuthorityRepository authorityRepository, PasswordEncoder passwordEncoder) {
        return args -> {
            var auths = Stream.of("ROLE_ADMIN", "ROLE_USER")
                    .map(Authority::new)
                    .toList();
            authorityRepository.saveAll(auths);
            var user = new User("user", passwordEncoder.encode("user"));
            user.setAuthorities(Set.of(authorityRepository.findByName("ROLE_USER")));

            var admin = new User("admin", passwordEncoder.encode("admin"));
            admin.setAuthorities(new HashSet<>(authorityRepository.findAll()));
            userRepository.saveAll(List.of(user, admin));
        };
    }
}

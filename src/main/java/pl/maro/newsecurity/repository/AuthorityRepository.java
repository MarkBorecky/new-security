package pl.maro.newsecurity.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import pl.maro.newsecurity.domain.Authority;

public interface AuthorityRepository extends JpaRepository<Authority, String> {
    Authority findByName(String name);
}

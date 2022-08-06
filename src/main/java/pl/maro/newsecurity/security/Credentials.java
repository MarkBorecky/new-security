package pl.maro.newsecurity.security;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

public class Credentials {
    @NotNull
    @Size(min = 1, max = 50)
    private String username;

    @NotNull
    @Size(min = 4, max = 100)
    private String password;

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }
}

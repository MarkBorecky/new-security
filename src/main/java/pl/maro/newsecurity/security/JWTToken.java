package pl.maro.newsecurity.security;

import com.fasterxml.jackson.annotation.JsonProperty;

public record JWTToken(
        @JsonProperty("id_token") String idToken
) {}

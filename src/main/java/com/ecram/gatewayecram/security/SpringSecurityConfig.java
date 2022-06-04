package com.ecram.gatewayecram.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.authorization.AuthenticatedReactiveAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import reactor.core.publisher.Mono;

@EnableWebFluxSecurity
public class SpringSecurityConfig {
    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public SecurityWebFilterChain configure(ServerHttpSecurity http) {
        return http.authorizeExchange()
                .pathMatchers("/api/oauth-ms/**").permitAll()
                .pathMatchers(HttpMethod.GET,
                        "/api/users-ms/v1/users/findUser/{username}").permitAll()
                .pathMatchers(HttpMethod.POST,
                        "/api/users-ms/v1/users/findUsers",
                        "/api/users-ms/v1/users/createUser").hasAnyRole("ADMIN", "USER")//No se coloca el prefijo ROL_ porque es automaticamente insertado
                .anyExchange().authenticated()
                .and().addFilterAt(jwtAuthenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .csrf().disable()
                .build();
    }


    private ReactiveAuthorizationManager<AuthorizationContext> checkUser(Mono<Authentication> authenticationMono) {
        authenticationMono.map(authentication -> {
           authentication.getAuthorities();
           authentication.getDetails();
           authentication.getPrincipal();
           return Mono.just(authentication);
        });
        return null;
    }

}

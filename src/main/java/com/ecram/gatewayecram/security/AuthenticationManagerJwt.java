package com.ecram.gatewayecram.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class AuthenticationManagerJwt implements ReactiveAuthenticationManager {
    @Value("${config.security.oauth.jwt.key}")
    private String jwtKey;


    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        //just convierte un objeto normal a uno reactivo, en este caso el token que se obtendra del JwtAuthenticationfilter
        return Mono.just(authentication.getCredentials().toString())
                .map(token->{
                    SecretKey keyForJwt = Keys.hmacShaKeyFor(Base64.getEncoder().encode(jwtKey.getBytes(StandardCharsets.UTF_8)));
                    return Jwts.parserBuilder().setSigningKey(keyForJwt).build().parseClaimsJws(token).getBody();//con Jws basta para tener los claims
                }).map(claims -> {//con map tendremos los claims del token
                    String userName = claims.get("user_name", String.class);
                    List<String> roles = claims.get("authorities", List.class);
                    Collection<GrantedAuthority> authorities = roles.stream().map(role-> new SimpleGrantedAuthority(role)).collect(Collectors.toList());
                    return new UsernamePasswordAuthenticationToken(userName, null, authorities);
                });
    }
}

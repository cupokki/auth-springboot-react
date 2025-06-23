package dev.cupokki.auth.config;

import dev.cupokki.auth.filter.JwtAuthenticationFilter;
import dev.cupokki.auth.jwt.JwtProvider;
import io.jsonwebtoken.Jwt;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtProvider jwtProvider;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter(jwtProvider);
    }


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .cors(cors -> cors.disable())
                .authorizeHttpRequests(auth -> auth
                                .requestMatchers("/api/v1/auth/**").permitAll()
                                .requestMatchers("/h2-console/**").permitAll()

//                        .requestMatchers("/api/v1/auth/login").permitAll()
//                        .requestMatchers("/api/v1/auth/reset-password").permitAll()
                        .anyRequest().authenticated()
                )
                .sessionManagement(session-> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(httpSecurityCsrfConfigurer -> httpSecurityCsrfConfigurer.disable())
                .headers(headers -> headers
                        .frameOptions(frame -> frame.sameOrigin()))

                .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
                .build();
    }
}

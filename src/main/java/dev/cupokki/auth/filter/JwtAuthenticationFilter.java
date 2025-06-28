package dev.cupokki.auth.filter;

import dev.cupokki.auth.exception.AuthenticationException;
import dev.cupokki.auth.jwt.JwtProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtProvider jwtProvider;
    private final FilterErrorResponseSender filterErrorResponseSender;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain filterChain
    ) throws ServletException, IOException {
        try{
            String authorizationHeader = request.getHeader("Authorization");

            log.info("Hi {}", authorizationHeader);
            if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
                String accessToken = authorizationHeader.substring(7);
                var userDetails = jwtProvider.getAuthentication(accessToken);
                SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities())
                );
            }
            filterChain.doFilter(request, response);
        } catch (AuthenticationException ex) {
            log.warn(ex.getAuthenticationErrorCode().getMessage());
            filterErrorResponseSender.send(request, response, ex);
        }

    }
}

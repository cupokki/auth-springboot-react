package dev.cupokki.auth.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader.isBlank() || !authorizationHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
        }

        String accessToken = authorizationHeader.substring(7);


//        JwtUtil.getAuthentication(accessToken);

        filterChain.doFilter(request, response);
    }
}

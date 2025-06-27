package dev.cupokki.auth.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.cupokki.auth.exception.AuthenticationException;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class FilterErrorResponseSender {

    private final ObjectMapper objectMapper;

    public void send(HttpServletResponse response, AuthenticationException ex) throws IOException {
        response.setStatus(ex.getAuthenticationErrorCode().getHttpStatus().value());
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        objectMapper.writeValue(response.getOutputStream(), ex.getMessage());
    }
}

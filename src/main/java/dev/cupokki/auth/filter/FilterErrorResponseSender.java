package dev.cupokki.auth.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.cupokki.auth.exception.AuthenticationException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URI;

@Component
@RequiredArgsConstructor
public class FilterErrorResponseSender {

    private final ObjectMapper objectMapper;

    public void send(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException ex
    ) throws IOException {
        ProblemDetail problem = ProblemDetail.forStatus(HttpStatus.UNAUTHORIZED);
        problem.setTitle("미인증");
        problem.setDetail(ex.getAuthenticationErrorCode().getMessage());
        problem.setInstance(URI.create(request.getRequestURI()));

        response.setStatus(ex.getAuthenticationErrorCode().getHttpStatus().value());
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        objectMapper.writeValue(response.getOutputStream(), problem);
    }
}

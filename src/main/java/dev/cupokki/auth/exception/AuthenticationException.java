package dev.cupokki.auth.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.ProblemDetail;

@Getter
@AllArgsConstructor
public class AuthenticationException extends RuntimeException{
    private AuthenticationErrorCode authenticationErrorCode;

    public ProblemDetail toProblemDetail() {
        return ProblemDetail.forStatusAndDetail(
                authenticationErrorCode.getHttpStatus(),
                authenticationErrorCode.getMessage()
        );
    }
}

package dev.cupokki.auth.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatusCode;

@Getter
@AllArgsConstructor
public class UserAuthenticationException extends RuntimeException{
    private String message;
    private HttpStatusCode httpStatusCode;

    static class UserNotFoundException extends UserAuthenticationException{
        public UserNotFoundException(String message, HttpStatusCode httpStatusCode) {
            super(message, httpStatusCode);
        }
    }
}

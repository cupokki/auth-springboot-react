package dev.cupokki.auth.exception;

import lombok.extern.slf4j.Slf4j;
import org.apache.tomcat.websocket.AuthenticationException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
@Slf4j
public class ExceptionAdviceHandler {

    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<?> runtimeExceptionHandler(RuntimeException e) {
        log.warn(e.getLocalizedMessage());
        return ResponseEntity.badRequest().body(e.getLocalizedMessage());
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<?> AuthenticationException(UserAuthenticationException e) {
        log.warn(e.getMessage());
        return ResponseEntity.status(e.getHttpStatusCode()).body(e.getMessage());
    }
}

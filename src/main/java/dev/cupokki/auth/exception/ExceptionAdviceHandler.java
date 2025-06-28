package dev.cupokki.auth.exception;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.ErrorResponseException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.net.URI;
import java.util.Locale;

@RestControllerAdvice
@Slf4j
public class ExceptionAdviceHandler {

    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<?> runtimeExceptionHandler(RuntimeException e) {
        log.warn(e.getLocalizedMessage());
        return ResponseEntity.badRequest().body(e.getLocalizedMessage());
    }

    @ExceptionHandler(ErrorResponseException.class)
    public ResponseEntity<?> AuthenticationException(ErrorResponseException ex) {
        log.warn(ex.getMessage());
        return ResponseEntity.status(ex.getStatusCode()).body(ex.getBody());
    }

    @ExceptionHandler(AuthenticationException.class)
    public ProblemDetail handleException(AuthenticationException ex, Locale locale) {
        log.warn(ex.getAuthenticationErrorCode().getMessage());
        return ex.toProblemDetail();
    }
}

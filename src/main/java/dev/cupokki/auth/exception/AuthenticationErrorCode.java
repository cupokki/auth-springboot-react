package dev.cupokki.auth.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;

@Getter
@AllArgsConstructor
public enum AuthenticationErrorCode {
    DUPLICATE_EMAIL(HttpStatus.BAD_REQUEST, "사용할 수 없는 이메일입니다."),
    INVALID_CREDENTIALS(HttpStatus.BAD_REQUEST, "이메일 또는 비밀번호가 일치하지않습니다."),
    CONFIRM_PASSWORD_MISMATCH(HttpStatus.BAD_REQUEST, "비밀번호 확인이 일치하지 않습니다.");

    private HttpStatus httpStatus;
    private String message;
}

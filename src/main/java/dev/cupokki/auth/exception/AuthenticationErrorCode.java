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
    CONFIRM_PASSWORD_MISMATCH(HttpStatus.BAD_REQUEST, "비밀번호 확인이 일치하지 않습니다."),
    INVALID_TOKEN_SIGNATURE(HttpStatus.UNAUTHORIZED, "토큰 서명이 올바르지 않습니다."),
    EXPIRED_TOKEN(HttpStatus.UNAUTHORIZED, "만료된 토큰입니다."),
    UNSUPPORTED_TOKEN_FORMAT(HttpStatus.UNAUTHORIZED, "잘못된 토큰 포멧 입니다."),
    INVALID_TOKEN_VALUE(HttpStatus.UNAUTHORIZED, "유효한 토큰 값이 아닙니다.");

    private HttpStatus httpStatus;
    private String message;
}

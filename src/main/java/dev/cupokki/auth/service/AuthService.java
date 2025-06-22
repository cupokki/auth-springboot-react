package dev.cupokki.auth.service;

import dev.cupokki.auth.dto.JwtTokenDto;
import dev.cupokki.auth.dto.UserSignUpRequest;
import dev.cupokki.auth.entity.User;
import dev.cupokki.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public JwtTokenDto login() {
        return JwtTokenDto.builder()
                .build();
    }

    public JwtTokenDto signup(UserSignUpRequest userSignUpRequest) {
        if (!userSignUpRequest.password().equals(userSignUpRequest.confirmPassword())) {
            throw new RuntimeException();
        }
        if (userRepository.existsByEmail(userSignUpRequest.email())) {
            throw new RuntimeException();
        }

        var newUser = User.builder()
                .email(userSignUpRequest.email())
                .username(userSignUpRequest.username())
                .password(passwordEncoder.encode(userSignUpRequest.password()))
                .build();

        userRepository.save(newUser);

        return this.login();
    }
}

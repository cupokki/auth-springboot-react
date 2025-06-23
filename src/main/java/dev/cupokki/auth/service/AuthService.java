package dev.cupokki.auth.service;

import dev.cupokki.auth.dto.JwtTokenDto;
import dev.cupokki.auth.dto.UserLoginRequest;
import dev.cupokki.auth.dto.UserSignUpRequest;
import dev.cupokki.auth.entity.User;
import dev.cupokki.auth.jwt.JwtProvider;
import dev.cupokki.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;

    public JwtTokenDto login(UserLoginRequest userLoginRequest) {
        var foundedUser = userRepository.findByEmail(userLoginRequest.email())
                .orElseThrow(RuntimeException::new);

        if (!passwordEncoder.matches(userLoginRequest.password(), foundedUser.getPassword())) {
            throw new RuntimeException();
        }

        return jwtProvider.createToken(foundedUser.getId(), userLoginRequest.isLongTerm());
    }

    public void signup(UserSignUpRequest userSignUpRequest) {
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

//        return jwtProvider.createToken(newUser.getId(), false);
    }
}

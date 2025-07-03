package com.example.jwt_demo.controller;

import com.example.jwt_demo.dto.AuthRequestDto;
import com.example.jwt_demo.dto.AuthResponseDto;
import com.example.jwt_demo.security.JwtTokenProvider;
import com.example.jwt_demo.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.Map;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthenticationManager authManager;
    private final JwtTokenProvider jwtProvider;
    private final UserService userService;

    // 회원가입(Sign-up)
    @PostMapping("/signup")
    public ResponseEntity<Void> signup(@RequestBody AuthRequestDto req) {
        userService.register(req.getEmail(), req.getPassword());
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    // 로그인(Login)
    @PostMapping("/login")
    public ResponseEntity<AuthResponseDto> login(@RequestBody AuthRequestDto req) {
        Authentication auth = authManager.authenticate(
                new UsernamePasswordAuthenticationToken(req.getEmail(), req.getPassword())
        );
        String accessToken = jwtProvider.generateAccessToken(req.getEmail());
        String refreshToken = jwtProvider.generateRefreshToken(req.getEmail());

        userService.saveRefreshToken(req.getEmail(), refreshToken);

        return ResponseEntity.ok(new AuthResponseDto(accessToken, refreshToken));
    }

    // RefreshToken 재발급 API
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponseDto> refresh
    (
        @RequestBody Map<String, String> request
    ) {
        String refreshToken = request.get("refreshToken");

        if (!jwtProvider.validateToken(refreshToken)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        String email = userService.validateRefreshToken(refreshToken);
        String newAccessToken = jwtProvider.generateAccessToken(email);
        String newRefreshToken = jwtProvider.generateRefreshToken(email);

        userService.saveRefreshToken(email, newRefreshToken);

        return ResponseEntity.ok(new AuthResponseDto(newAccessToken, newRefreshToken));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestBody Map<String, String> request) {
    String refreshToken = request.get("refreshToken");
    if (refreshToken != null && jwtProvider.validateToken(refreshToken)) {
        String email = jwtProvider.getEmail(refreshToken);
        userService.deleteRefreshToken(email);
    }
    return ResponseEntity.noContent().build();
}
}

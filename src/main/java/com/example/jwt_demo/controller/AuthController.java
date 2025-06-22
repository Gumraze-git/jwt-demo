package com.example.jwt_demo.controller;

import com.example.jwt_demo.security.JwtTokenProvider;
import com.example.jwt_demo.service.UserService;
import lombok.*;
import org.springframework.http.*;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthenticationManager authManager;
    private final JwtTokenProvider jwtProvider;
    private final UserService userService;

    /** 회원가입(Sign-up) */
    @PostMapping("/signup")
    public ResponseEntity<Void> signup(@RequestBody AuthRequest req) {
        userService.register(req.getEmail(), req.getPassword());
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    /** 로그인(Login) */
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody AuthRequest req) {
        Authentication auth = authManager.authenticate(
                new UsernamePasswordAuthenticationToken(req.getEmail(), req.getPassword())
        );
        String token = jwtProvider.generateToken(req.getEmail());
        return ResponseEntity.ok(new AuthResponse(token));
    }

    @Data
    static class AuthRequest {
        private String email;
        private String password;
    }

    @Data
    @AllArgsConstructor
    static class AuthResponse {
        private String token;
    }
}

package com.example.jwt_demo.controller;

import com.example.jwt_demo.dto.AuthRequestDto;
import com.example.jwt_demo.dto.AuthResponseDto;
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
    public ResponseEntity<Void> signup(@RequestBody AuthRequestDto req) {
        userService.register(req.getEmail(), req.getPassword());
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    /** 로그인(Login) */
    @PostMapping("/login")
    public ResponseEntity<AuthResponseDto> login(@RequestBody AuthRequestDto req) {
        Authentication auth = authManager.authenticate(
                new UsernamePasswordAuthenticationToken(req.getEmail(), req.getPassword())
        );
        String token = jwtProvider.generateToken(req.getEmail());
        return ResponseEntity.ok(new AuthResponseDto(token));
    }
}

package com.example.jwt_demo.service;

import com.example.jwt_demo.entity.User;
import com.example.jwt_demo.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService implements UserDetailsService {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    // 회원가입 처리
    @Transactional
    public User register(String email, String password) {
        // 이메일 중복 체크
        if (userRepository.existsByEmail(email)) {
            throw new IllegalArgumentException("[에러] 이미 사용 중인 이메일입니다.");
        }
        // 비밀번호 암호화
        String encoded = passwordEncoder.encode(password);
        User user = User.builder()
                        .email(email)
                        .password(encoded)
                        .build();

        // 암호화된 비밀번호 저장
        return userRepository.save(user);
    }

    // Spring Security 인증을 위한 사용자 정보 로드
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("[에러] 등록되지 않은 이메일입니다."));

        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getEmail())
                .password(user.getPassword())
                .roles("USER")
                .build();
    }
}

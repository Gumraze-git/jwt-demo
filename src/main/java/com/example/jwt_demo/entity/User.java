package com.example.jwt_demo.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id; // 엔티티 식별자, 자동 생성

    @Column(unique = true, nullable = false)
    private String email; // 사용자 이메일

    @Column(nullable = false)
    private String password; // 사용자 비밀번호
}

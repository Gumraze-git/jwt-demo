- - -
# 개요
Spring Boot 애플리케이션에서 JWT(JSON Web Token)를 활용한 인증(Authentication) 및 인가(Authorization) 기능을 구현 및 시연함.  
클라이언트는 로그인 또는 회원가입 시 받은 토큰을 이용하여 사용자 신원을 확인하고 권한을 관리함.

# 1. 프로젝트 설정
## 1.1 Spring initializr
- Project Gradle
- Spring boot: 3.5
- Artifact: `jwt-demo`
- Name: `jwt-demo`
- Packaging: Jar
- Java: 17

## 1.2 의존성 추가
- Spring Web
- Spring Security
- Spring Boot Devtools
- Spring Data JPA
- MySQL
- Lombok
> JWT 관련 라이브러리는 `build.gradle`에 직접 추가함.

## 1.3 Gradle에 JWT 의존성 추가
- **전체 코드**
```gradle
implementation 'io.jsonwebtoken:jjwt-api:0.11.5'    // JWT 생성 및 파싱을 위한 인터페이스 및 빌더 제공
runtimeOnly   'io.jsonwebtoken:jjwt-impl:0.11.5'    // HS256, RSA 등의 서명 알고리즘 핸들러와 파싱 로직의 구현을 담고 있는 라이브러리
runtimeOnly   'io.jsonwebtoken:jjwt-jackson:0.11.5' // JSON으로 작성된 JWT 페이로드를 직렬화 및 역직렬화 하기위한 바인딩 모듈
```

- JJWT 라이브러리를 통해 JWT 생성, 파싱 및 JSON 파인딩 기능을 제공한다.
> 위 `runtimeOnly`는 컴파일 시에는 API만 참조하고, 애플리케이션 실행 시에만 이 구현체가 로드되어 최소한의 의존성으로 빌드 속도 및 용량을 최적화 한다.

- - -
# 2. 애플리케이션 설정
## `application.properties`
```properties
# 서버 정보(포트: 8080)
spring.application.name=jwt-demo
server.port=8080

# JDBC 연결 설정
# JDBC URL: MySQL 호스트, 포트, 스키마, SSL, 타임존 저장
spring.datasource.url=jdbc:mysql://localhost:3306/jwt_demo?useSSL=false&serverTimezone=UTC

# DB 접속 계정 정보
spring.datasource.username=jwt_user
spring.datasource.password=1234

# JPA/Hibernate 설정
# 애플리케이션 시작 시 엔티티와 스키마를 비교하여 자동으로 반영함.
spring.jpa.hibernate.ddl-auto=update
# 실행되는 SQL문을 콘솔에 출력함.
spring.jpa.show-sql=true
# 출력되는 SQL문을 읽기 쉽게 포맷팅함.
spring.jpa.properties.hibernate.format_sql=true

# JWT 서명에 사용할 비밀키
jwt.secret = pW3f7nKL4uTaBv5QsFgYtRu6Zx9e1nKcLxPmGwHcRp3JtLkYzVcBaSpZrWqTxYhU
```
- JWT 서명에 사용되는 비밀 키는 실제 배포에는 `application.properties`에 포함되면 안된다.

- - -
# 3. 데이터베이스 구성(MySQL)

- 데이터베이스: `jwt_demo`
- 사용자 계정: `jwt_user`
- 비밀번호: `1234`

- DB 구성 방법을 아는 경우에는 [다음](#패키지-구조)으로 넘어가도 됩니다. 
> DB 구성은 macOS를 기준으로 작성되었습니다.

- - -
## 3.1 Homebrew 설치
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

## 3.2 MySql 설치
### 3.2.1 호환성을 위해 MySQL 8.0 버전을 설치함.
```bash
brew install mysql@8.0
```

### 3.2.2 MySQL 서버 시작 및 macOS 부팅 시 자동으로 MySQL이 구동되도록 설정
```bash
brew services start mysql
```

### 3.2.3 MySQL이 실행되고 있는지 확인
```bash
brew services list
```

- 다음 정보가 출력되면 MySQL이 실행되고 있음을 확인할 수 있다.
```bash
mysql@8.0 started USER_NAME ~/Library/LaunchAgents/homebrew.mxcl.mysql@8.0.plist
```

### 3.2.4 DB 초기 보안 설정
```bash
mysql_secure_installation
```

- root 비밀번호 설정
- 익명 사용자 제거: `Y`
- 원격 root 로그인 차단: `Y`
- 테스트 데이터베이스 제거: `Y`
- 권한 테이블 즉시 재로드: `Y`

### 3.2.5 데이터베이스 및 전용 사용자 생성
- MySQL에 `root` 계정으로 접속
```bash
mysql -u root -p
```

- JWT demo를 위한 db 생성 및 사용자 생성
```sql
-- 1. 애플리케이션용 데이터베이스 생성
CREATE DATABASE jwt_demo;

-- 2. 전용 사용자 생성 및 최소 권한 부여
CREATE USER 'jwt_user'@'localhost' IDENTIFIED BY '1234';
GRANT ALL ON jwt_demo.* TO 'jwt_user'@'localhost';
```

- MySQL 쉘에서 다음을 입력하여 `jwt_demo`가 있는지 확인
```sql
SHOW DATABASES;
```

**예시)**
```pgsql
+--------------------+
| Database           |
+--------------------+
| jwt_demo           |
| mysql              |
| ...                |
+--------------------+
```

- 사용자 계정 확인
```sql
SELECT User, Host
FROM mysql.user
WHERE User = 'jwt_user';
```

다음이 나타나면 사용자 계정이 정상적으로 생성됨을 확인할 수 있다.
```pgsql
+----------+-----------+
| User     | Host      |
+----------+-----------+
| jwt_user | localhost |
+----------+-----------+
```

위 MySQL까지 설정 후 `JwtDemoApplication`을 실행했을 때, 오류 없이 서버가 실행되면 기본 설정은 완료이다.

- - -
# 4. 패키지 구조
```text
src/main/java/com/example/jwtdemo
├── JwtDemoApplication.java
├── config
│   ├── PasswordConfig
│   └── SecurityConfig
├── controller
│   └── AuthController
├── dto
│   ├── AuthRequestDto
│   └── AuthResponseDto
├── entity
│   └── User
├── repository
│   └── UserRepository
├── security
│   ├── JwtTokenProvider
│   └── JwtAuthenticationFilter
└── service
    └── UserService
```
- - -
# 5. 코드 구현
## 5.1 Entity
### 5.1.1 User
```java
@Entity // 이 클래스가 Entity임을 명시함.
@Getter @Setter // get, set 메서드를 자동으로 생성함.
@NoArgsConstructor // 매개변수 없는 생성자를 생성함.
@AllArgsConstructor // 매개변수가 있는 생성자를 생성함.
@Builder // 빌더 패턴 기반의 객체 생성 코드를 자동으로 생성해주는 애너테이션
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
```

- - -
## 5.2 Repository
### 5.2.1 UserRepository
```java
public interface UserRepository extends JpaRepository<User, Long> {
  // 이메일로 사용자 조회
  Optional<User> findByEmail(String email);

  // 이메일 중복 확인
  boolean existsByEmail(String email);
}
```
- `JpaRepository`: Spring Data JPA가 제공하는 인터페이스 중 하나로, JPA를 이용하여 데이터 접근 계층(Data Access Layer)을 매우 간편하게 만들어준다.
- `JpaRepository`를 상속 받으면, 다음과 같은 메서드들이 자동으로 구현되어 사용가능하다.

| 범주       | 메서드 예시                              | 설명                           |
|----------|-------------------------------------|------------------------------|
| 생성 및 수정  | `save(S entity)`                    | 엔티티를 저장하거나(신규 생성) 업데이트       |
| 조회       | `findById(ID id)`                   | 식별자로 단건 조회(`Optional<T>` 반환) |
|          | `findAll()`                         | 전체 목록 조회                     |
| 삭제       | `deleteById(ID id)`                 | 식별자로 삭제                      |
|          | `delete(T entity)`                  | 엔티티 인스턴스로 삭제                 |
| 카운트      | `count()`                           | 전체 개수 조회                     |
| 페이징 및 정렬 | `findAll(Pageable pageable`         | 페이징 및 정렬 조건에 따른 목록 조회        |
| 벌크       | `flush()`, `saveAndFlush(S entity)` | 즉시 반영(Flush) 관련 메서드          |


- 메서드
  - `findByEmail`과 `existByEmail` 메서드는 회원가입과 인증 과정에서 이메일을 기준으로 사용자를 조회 및 검증하는데 사용된다.
  
- - -
## 5.3 Service
### 5.3.1 UserService
```java
@Service // 스프링 컨테이너에 이 클래스를 서비스 빈(Service Bean)으로 등록함.
@RequiredArgsConstructor // final 필드를 파라미터로 받는 생성자를 자동으로 생성함.
public class UserService implements UserDetailsService {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    // 회원 가입 처리
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
```
- `UserDetailService`: Spring Security의 인증 처리 인터페이스로 `loadUserByUsername` 메서드로 로그인 프로세스 중 사용자 정보를 가져오는 역할을 한다.
  - `loadUserByUsername`: 반환된 `UserDetails`를 통해 비밀번호 비교와 권한 검증이 이루어진다.
- `@Transactional`: 메서드 전체를 하나의 트랜잭션으로 묶어, 성공 시 커밋, 예외 시 롤백하여 데이터의 정합성을 보장한다.
- 메서드
  - `register`
    - 이메일 중복 검사: 이미 존재하는 이메일이면 예외를 던져 중복 가입을 방지한다.
    - 비밀번호 암호화: 평문 비밀번호를 `BCryptPasswordEncoder`를 이용해 해시로 변환하여 DB에 저장한다.
      - 비밀번호 유출 시에도 원문을 알 수 없도록 한다.
    - 엔티티 생성 및 저장: `builder()` 패턴으로 `User` 객체를 생성하고 `save()` 호출로 영속화한다.

- - -
## 5.4 Security
### 5.4.1 JwtTokenProvider
```java
@Component
@RequiredArgsConstructor
public class JwtTokenProvider {
  private final UserDetailsService userDetailsService;
  @Value("${jwt.secret}")
  private String secretKey;

  @Value("${jwt.expiration-ms}")
  private long validityInMilliseconds;

  @PostConstruct
  protected void init() {
    // 시크릿 키를 Base64로 인코딩: JWT 서명 단계에서 필요한 키를 안전한 문자열 형태로 변환해둠.
    secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
  }

  // 사용자 이름(email)으로 JWT 생성
  public String generateToken(String email) {
    Claims claims = Jwts.claims().setSubject(email);
    Date now = new Date();
    Date expiryDate = new Date(now.getTime() + validityInMilliseconds);

    return Jwts.builder()
            .setClaims(claims)
            .setIssuedAt(now)
            .setExpiration(expiryDate)
            .signWith(SignatureAlgorithm.HS256, secretKey)
            .compact();
  }

  // JWT에서 인증 정보 추출
  public Authentication getAuthentication(String token) {
    // getEmail: 토큰에서 이메일 추출
    // UserDetailsService로부터 사용자 정보를 조회함.
    UserDetails userDetails = userDetailsService.loadUserByUsername(getEmail(token));
    return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
  }

  // 토큰에서 email 추출
  private String getEmail(String token) {
    return Jwts.parser()
            .setSigningKey(secretKey)
            .parseClaimsJws(token)
            .getBody()
            .getSubject();
  }

  // 토큰 유효성 검사
  public boolean validateToken(String token) {
    try {
      // parseClaimsJws 호출으로 서명 오류나 만료된 토큰이면 예외가 발생함.
      Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);
      return true;
    } catch (Exception e) {
      return false;
    }
  }
}

```
- 비밀 키 초기화(`init()`)
  - JWT를 안전하게 서명(signature)하기 위해, 설정된 문자열을 Base64로 인코딩한다.
- 토큰 생성(`generateToken`)
  - 이메일을 "누구를 위한 토큰인지" 나타내는 subject(서브젝트)로 담고,
  - 발행시간 및 만료시간을 설정한 뒤,
  - 비밀키로 HS256 알고리즘 서명을 해 하나의 긴 문자열(JWT)로 만든다.
- 토큰 검증 및 인증 정보 획득
  - `validateToken`: 해당 토큰이 우리의 비밀키로 맞는지(서명 확인)? 및 아직 만료되지 않았는지? 를 검사한다.
  - `getEmail`: `validateToken`을 통과하면 `getEmail`으로 누구를 위한 토큰인지(서브젝트)를 꺼낸다.
  - `getAuthentication`: 다음 메서드로 Spring Security가 이해할 수 있는 `Authentication` 객체로 바꾸어준다.

다음 과정을 통해 클라이언트가 요청마다 JWT를 헤더에 함께 보내면, 서버는 이 사람이 누구인지 확인하고, 위변조된 토큰인지 자동으로 확인하여 걸러준다.

### 5.4.2 JwtAuthenticationFilter
```java
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
  private final JwtTokenProvider tokenProvider;

  @Override
  protected void doFilterInternal(HttpServletRequest request,
                                  HttpServletResponse response,
                                  FilterChain filterChain)
          throws IOException, ServletException {
    String bearer = request.getHeader("Authorization");
    if (bearer != null && bearer.startsWith("Bearer ")) {
      String token = bearer.substring(7);
      if (tokenProvider.validateToken(token)) {
        var auth = tokenProvider.getAuthentication(token);
        SecurityContextHolder.getContext().setAuthentication(auth);
      }
    }
    filterChain.doFilter(request, response);
  }
}

```
- `OncePerRequestFilter`
  - 스프링이 제공하는 추상 필터로, HTTP 요청당 한 번만 실행된다.
  - 이 필터를 통해 모든 요청에 대하여 JWT 검사 로직을 일괄 적용할 수 있다.
- 메서드
  - `doFilterInternal`
    - 토큰 추출: `request.getHeader("Authorization")`으로 Authorization 헤더 값을 읽어온다.
  - `Bearer ` 검사 및 파싱
    - 토큰을 `Bearer` 접두어를 제외한 다음 부분만 남도록 한다.
  - 유효성 검사
    - `tokenProvider.validateToken(token)`으로 서명과 만료 시간을 검증한다.
  - 인증 객체 생성
    - `tokenProvider.getAuthentication(token)` 호출 시, 토큰 내 이메일(서브젝트)로 유저를 조회하고 `Authentication` 객체를 생성한다.
  - SecurityContext 세팅
    - `SecurityContextHolder.getContext().setAuthentication(auth)` 로 인증 정보를 보관하면, 이후 스프링 시큐리티가 `@AuthenticationPrincipal` 등을 통해 사용자 정보를 사용할 수 있다.

즉, 모든 요청마다 `Authorization` 헤더에 담긴 JWT를 꺼내어,
**유효하면** 스프링 시큐리티의 인증 컨텍스트에 로그인 정보를 등록한 뒤,
다음 필터(컨트롤러)로 요청을 넘기는 역할을 한다.

## 5.5 Config
### 5.5.1 SecurityConfig
```java
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
  private final JwtTokenProvider tokenProvider;
  private final UserService userService;
  private final PasswordEncoder passwordEncoder;

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    // JWT 인증 필터
    JwtAuthenticationFilter jwtFilter = new JwtAuthenticationFilter(tokenProvider);

    http
            .csrf(csrf -> csrf.disable())
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                    .requestMatchers("/auth/**").permitAll()
                    .anyRequest().authenticated()
            )
            .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

    return http.build();
  }

  @Bean
  public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
    // 1. HttpSecurity로부터 AuthenticationManagerBuilder 인스턴스를 꺼냄.
    AuthenticationManagerBuilder authBuilder =
            http.getSharedObject(AuthenticationManagerBuilder.class);

    // 2. userDetailsService와 passwordEncoder를 설정함.
    authBuilder
            .userDetailsService(userService)
            .passwordEncoder(passwordEncoder);

    // 3. AuthenticationManager를 빌드하여 반환함.
    return authBuilder.build();
  }
}
```
- Lombok
  - `@EnableWebSecurity`
    - Spring Security의 웹 보안 기능을 활성화하며, 내부적으로 여러 보안 필터를 자동 등록할 준비를 한다.
- 메서드
  - `filterChain`
    - Spring Security의 필터 체인을 구성하는 메서드이다.
    - CSRF 비활성화: REST API 서버는 세션 기반이 아니므로 필요하지 않다.
    - 세션 비활성화: JWT 기반이므로 서버를 상태를 저장하지 않으므로 `STATELESS`로 설정한다.
    - 경로별 접근 제어: `/auth/**`은 모두 허용하며, 그 외에는 인증이 필요하다.
    - JWT 필터 삽입: `UsernamePasswordAuthenticationFilter` 이전, `JwtAuthenticationFilter`를 넣어 요청마다 JWT를 검사할 수 있게 한다.
  - `authenticationManager`
    - 사용자 로그인 시 인증 매니저가 호출되어 실제 인증을 수행한다.
    - `UserService`를 통해 사용자를 로드, `PasswordEncoder`로 비밀번로를 매칭 방식으로 설정한 뒤,
    - 최종적으로 `AuthenticationManager` 빈을 생성해준다.

- - -
## 5.6 Controller
### 5.6.1 AuthController
```java
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
```
- - -
## 5.7 DTO
데이터 전송 객체 생성
### 5.7.1 AuthRequestDto
```java
package com.example.jwt_demo.dto;

import lombok.Data;

@Data
public class AuthRequestDto {
    private String email;
    private String password;
}
```
### 5.7.2 AuthResponseDto
```java
package com.example.jwt_demo.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class AuthResponseDto {
    private String token;
}

```

# 6. 테스트 및 검증
## 6.1 회원가입
- 요청: POST /auth/signup
```json
{ "email": "user@example.com", "password": "password123" }
```
- 응답: 201 Created

## 6.2 로그인
- 요청: POST /auth/login
```json
{ "email": "user@example.com", "password": "password123" }
```
- 응답
```json
{ "token": "<JWT>" }
```
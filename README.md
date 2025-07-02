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

# DB가 MySQL을 사용했다는 것을 명시(선택)
spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver
spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.MySQL8Dialect

# JPA/Hibernate 설정
# 애플리케이션 시작 시 엔티티와 스키마를 비교하여 자동으로 반영함.
spring.jpa.hibernate.ddl-auto=update
# 실행되는 SQL문을 콘솔에 출력함.
spring.jpa.show-sql=true
# 출력되는 SQL문을 읽기 쉽게 포맷팅함.
spring.jpa.properties.hibernate.format_sql=true

# JWT 서명에 사용할 비밀키
jwt.secret = pW3f7nKL4uTaBv5QsFgYtRu6Zx9e1nKcLxPmGwHcRp3JtLkYzVcBaSpZrWqTxYhU

# JWT 토큰 만료 시간 설정
jwt.access-token.expiration-ms=3600000
jwt.refresh-token.expiration-ms=1209600000
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
CREATE USER 'jwt_demo'@'localhost' IDENTIFIED BY '1234';
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

### 5.1.2 RefreshToken
```java
@Entity
@Getter @Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Table(name = "refresh_tokens")
public class RefreshToken {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false)
    private String token;
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

### 5.2.1 RefreshTokenRepository
```java
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByEmail(String email);
    Optional<RefreshToken> findByToken(String token);
    void deleteByEmail(String email);
}
```

- - -
## 5.3 Service
### 5.3.1 UserService
```java
@Service // 스프링 컨테이너에 이 클래스를 서비스 빈(Service Bean)으로 등록함.
@RequiredArgsConstructor // final 필드를 파라미터로 받는 생성자를 자동으로 생성함.
public class UserService implements UserDetailsService {
  private final UserRepository userRepository;
  private final PasswordEncoder passwordEncoder;
  private final RefreshTokenRepository refreshTokenRepository;

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

  // 로그인 시 RefreshToken 저장 또는 갱신
  @Transactional
  public void saveRefreshToken(String email, String token) {
    RefreshToken refreshToken = refreshTokenRepository.findByEmail(email)
            .map(rt -> {
              rt.setToken(token);
              return rt;
            })
            .orElse(RefreshToken.builder()
                    .email(email)
                    .token(token)
                    .build());
    refreshTokenRepository.save(refreshToken);
  }

  // 유효한 refresh token인지 확인하고 이메일을 반환
  @Transactional
  public String validateRefreshToken(String token) {
    return refreshTokenRepository.findByToken(token)
            .map(RefreshToken::getEmail)
            .orElseThrow(() -> new RuntimeException("[에러] 유효하지 않은 Refresh Token입니다."));
  }

  // 로그아웃 또는 재발급 시 기존 refresh token 삭제
  @Transactional
  public void deleteRefreshToken(String email) {
    refreshTokenRepository.deleteByEmail(email);
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

  // refresh API 추가
  @PostMapping("/refresh")
  public ResponseEntity<AuthResponseDto> refresh(@RequestBody Map<String, String> request) {
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
}
```
- - -
## 5.7 DTO
데이터 전송 객체 생성
### 5.7.1 AuthRequestDto
```java
@Data
public class AuthRequestDto {
    private String email;
    private String password;
}
```
### 5.7.2 AuthResponseDto
```java
@Data
@AllArgsConstructor
public class AuthResponseDto {
  private String accessToken;
  private String refreshToken;
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

## 6.3 Refresh Token 재발급
- 요청: POST /auth/refresh
```json
{
  "refreshToken": "my-refresh-token"
}
```

- 응답
```json
{
  "accessToken": "<new-access-token>",
  "refreshToken": "<new-refresh-token>"
}
```

- - -
# 7. 전체 흐름
## 7.1 회원가입(Sign-up)
- 클라이언트가 `/auth/signup` 요청을 보냄
- `AuthController.signup()`에서 `UserService.register()` 호출 → `UserRepository`를 통해 DB에 신규 사용자 저장 → 201 Created 응답 반환. 

## 7.2 로그인(Login)
- 클라이언트가 `/auth/login` 요청(이메일, 비밀번호) 전송.
- `AuthController.login()`에서 `AuthenticationManager.authenticate()` 실행 → `UserService.loadUserByUsername()`로 사용자 로드 및 `BCryptPasswordEncoder`로 비밀번호 검증.
- 인증 성공 시 `JwtTokenProvider.generateToken()` 호출 → 이메일을 Subject로 설정하고 HS256 알고리즘으로 서명한 JWT 생성 → `AuthResponseDto`에 토큰을 담아 반환.

## 7.3 요청 필터링 및 인증 컨텍스트 설정
- 클라이언트가 보호된 API에 접근할 때마다 HTTP 헤더 `Authorization: Bearer <JWT>` 포함.
- `JwtAuthenticationFilter.doFilterInternal()`이 모든 요청에 실행됨:
  - 헤더에서 `Bearer` 토큰 추출
  - `JwtTokenProvider.validateToken()`로 서명 및 만료 검증
  - 유효한 토큰일 경우 `JwtTokenProvider.getAuthentication()` 호출 → `UsernamePasswordAuthenticationToken` 생성
  - `SecurityContextHolder`에 인증 정보 저장 → 이후 컨트롤러에서 `@AuthenticationPrincipal` 등으로 사용자 정보 사용 가능

## 7.4 보호된 리소스 처리
- `SecurityConfig`의 설정에 따라 `/auth/**` 외 모든 요청은 인증 필요.
- `SecurityContextHolder`에 인증된 사용자가 존재하면, 해당 권한(ROLE_USER)으로 컨트롤러 메서드 실행.
- 인증 정보가 없거나 토큰이 유효하지 않으면 401 Unauthorized 응답 발생.

## 7.5 토큰 재발급(Refresh)
- `accessToken`이 만료되었을 경우, 클라이언트는 저장된 `refreshToken`을 `/auth/refresh` API로 전달한다.
- 서버는 `refreshToken`의 유효성을 검증하고 DB에 저장된 토큰과 일치 여부를 확인한 뒤,
- 새로운 `accessToken`과 `refreshToken`을 생성하여 응답한다.
- 클라이언트는 응답 받은 토큰을 이용하여 이후 요청을 이어간다.

- - -
# 8. 개념 설명
## 8.1 JWT 개요
### 8.1.1 JWT?
- JWT는 JSON Web Token의 약자로, 사용자 인증(Authentication) 및 정보 전달에 사용되는 토큰 기반의 인증 방식이다.
- 클라이언트와 서버 사이의 안전한 정보 전달을 위해 `Base64Url`로 인코딩된 JSON 객체를 사용한다.

### 8.1.2 왜 JWT를 사용하는가?
#### 기존 세션 기반 인증 방식의 한계
전통적인 웹 인증 방식은 서버 세션 기반으로 다음과 같은 형태를 가지고 있다.
1. 사용자가 로그인하면 서버가 세션을 생성하고 세션 ID를 발급
2. 세션 ID를 클라이언트가 쿠키로 저장하고, 이후 요청 시 함께 요청
3. 서버는 요청마다 이 세션 ID를 확인하고 인증 여부를 판단함.

**문제점**
- 서버가 사용자별 세션 정보를 메모리 혹은 DB에 저장해야함.
- 서버가 늘어날수록 세션 공유 또는 세션 저장소의 중앙화 필요함.
- 수평 확장에 적합하지 않음(특히 클라우드, 마이크로서비스 환경)

즉, 서버 관리에 많은 노력(비용)과 병목이 발생한다.

#### JWT 기반 인증 방식
- JWT는 이러한 문제를 해결하고자 다음과 같은 목표로 설계됨.
  - 서버가 상태를 유지하지 않아도 됨(Stateless)
  - 인증 정보를 클라이언트에게 토큰 형태로 위임
  - 토큰만 있으면 어디서든 인증이 가능함.

**문제점**
- 토큰이 도난당하면 사용자의 정보를 누구나 사용할 수 있게됨
  - https 등의 보안 강화가 필요함.
- 만료 시간 이전에 권한 변경이 어려우며, 만료가 되지 않은 토큰을 취소할 방법이 복잡함.
  - 도난 토큰의 블랙리스트가 필요함.

## 8.2 JWT 구조
JWT는 다음과 같이 세 부분으로 구성되어 있다.

```text
Header.Payload.Signature
```

**구성요소**
- `Header`: 토큰 타입과 서명 알고리즘
- `Payload`: 전달할 클레임(사용자 정보)
- `Signature`: 비밀 키를 이용해 서명한 값, 위조 방지 목적

## 8.3 JWT 사용 흐름
1. 사용자 로그인
2. 서버는 로그인 성공 시, **Access Token과 Refresh Token** 발급함.
3. 클라이언트(사용자)는 Access Token을 헤더(Authorization: Bearer<token>)에 포함시켜 요청
4. 서버는 토큰 검증 후 요청 처리
5. Access Token이 만료되면, Refresh Token으로 재발급 요청
6. 서버는 Refresh Token 검증 후 새로운 Access Token 발급

## 8.4 Access Token vs Refresh Token
|구분|Access Token| Refresh Token|
|---|---|---|
|목적| API 접근 허용| Access Token 재발급|
|유효기간| 짧음(n분)| 김(n day)|
|저장 위치| 브라우저 메모리, HttpOnly 쿠키| HttpOnly 쿠키 또는 서버|
|노출 위험| 비교적 높음| 보안이 더 중요함|

## 8.5 동작 예시

### 8.5.1 입력
사용자가 인증 요청(로그인)을 서버에 다음과 같은 데이터를 보냄.

```text
POST /auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "mypassword123"
}
```
- 입력 항목
  - `email`: 사용자의 고유 이메일 주소
  - `password`: 해당 이메일에 해당하는 비밀번호

### 8.5.2 처리 과정
|순서|단계| 설명                            |
|--|--|-------------------------------|
|1|사용자 조회| 입력받은 이메일로 사용자 존재 여부 확인(DB) 조회 |
|2|비밀번호 검증| 입력된 비밀번호와 DB에 저장된 해시 비교|
|3| 유효성 판단| 비밀번호 일치하면 인증 성공, 아니면 실패 응답|
|4|JWT Payload 구성| 사용자 ID, 이메일, 권한, 발급 시간 등 포함|
|5| 토큰 서명 및 생성| accessToken, refreshToken 각각 서명 후 발급|
|6| 응답 반환| 생성된 토큰을 클라이언트에 반환|

**JWT Payload 예시**
```json
{
  "sub": "user_id_123",
  "email": "user@example.com",
  "role": "user",
  "iat": 1722350000,
  "exp": 172235360
}
```
### 8.5.3 출력
서버가 클라이언트에게 JWT를 반환함.

```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```
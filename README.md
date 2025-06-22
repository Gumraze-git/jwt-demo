# Spring initializr 설정
- Project Gradle
- Spring boot: 3.5
- Artifact: `jwt-demo`
- Name: `jwt-demo`
- Packaging: Jar
- Java: 17

## 의존성
- Spring Web
- Spring Security
- Spring Boot Devtools
- Spring Data JPA
- MySQL
- Lombok

> JWT 관련 라이브러리는 `build.gradle`에 직접 추가함.

### JWT 라이브러리
#### Gradle

- JJWT 라이브러리 추가
```gradle
implementation 'io.jsonwebtoken:jjwt-api:0.11.5'
runtimeOnly   'io.jsonwebtoken:jjwt-impl:0.11.5'
runtimeOnly   'io.jsonwebtoken:jjwt-jackson:0.11.5'
```

```gradle
implementation 'io.jsonwebtoken:jjwt-api:0.11.5'
```
- JJWT(Java JWT) 라이브러리의 API 모듈을 컴파일 및 런타임에 의존성으로 추가한다.
- 애플리케이션 코드에서 JWT 관련 기능을 호출할 때 참조하는 모듈로 컴파일 시점에도 필요하다.
- JWT 생성 및 파싱을 위한 핵심 인터페이스와 빌더를 다음과 같이 제공한다.
  - `Jwts.builder()`
  - `Claims`
  - etc..

```gradle
runtimeOnly   'io.jsonwebtoken:jjwt-impl:0.11.5'
```
- JJWT API에서 정의한 기능을 실제로 동작시키는 "구현체" 모듈을 런타임 클래스패스에만 포함한다.
- HMAC, RSA 등의 서명 알고리즘 핸들러와 파싱 로직 등의 실제 구현을 담고 있다.
- 위 `runtimeOnly`는 컴파일 시에는 API만 참조하고, 애플리케이션 실행 시에만 이 구현체가 로드되어 최소한의 의존성으로 빌드 속도 및 용량을 최적화 한다.

```gradle
runtimeOnly   'io.jsonwebtoken:jjwt-jackson:0.11.5'
```
- JWT 페이로드(JSON)를 Jackson 라이브러리로 직렬화 및 역직렬화하기 위한 바인딩 모듈을 런타임에만 포함한다.
  - `Claims` 객체를 JSON으로 바꾸거나 JSON 문자열을 `Claims`로 변환할 때 Jackson 애너테이션과 mapper 설정을 제공한다.
- 애플리케이션에 Jackson이 있을 때, 자동으로 JSON 처리 로직이 동작해 주어, API와 구현체 모듈만으로는 처리할 수 없는 JSON 바인딩 기능을 추가한다.

### JPA 및 JDBC 설정
```properties
# 애플리케이션 식별 이름
spring.application.name=jwt-demo

# 내장 톰캣이 리스닝할 포트
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

# DB(MySQL) 구성
- `application.properties`에 설정된 JDBC 정보
  - 데이터베이스 이름: `jwt_demo`
  - 사용자 이름: `jwt_user`
  - 비밀번호: `1234`

- DB 구성 방법을 아는 경우에는 다음으로 넘어가도 됩니다. 
> DB 구성은 macOS를 기준으로 작성되었습니다.


### 1. Homebrew 설치
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

### 2. MySql 설치
#### (1) 호환성을 위해 MySQL 8.0 버전을 설치함.
```bash
brew install mysql@8.0
```

#### (2) MySQL 서버 시작 및 macOS 부팅 시 자동으로 MySQL이 구동되도록 설정
```bash
brew services start mysql
```

#### (3) MySQL이 실행되고 있는지 확인
```bash
brew services list
```

- 다음 정보가 출력되면 MySQL이 실행되고 있음을 확인할 수 있다.
```bash
mysql@8.0 started USER_NAME ~/Library/LaunchAgents/homebrew.mxcl.mysql@8.0.plist
```

#### (4) DB 초기 보안 설정
```bash
mysql_secure_installation
```

- root 비밀번호 설정
- 익명 사용자 제거: `Y`
- 원격 root 로그인 차단: `Y`
- 테스트 데이터베이스 제거: `Y`
- 권한 테이블 즉시 재로드: `Y`

#### (5) 데이터베이스 및 전용 사용자 생성
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

예시
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


# 패키지 구조
```text
src/main/java/com/example/jwtdemo
├── JwtDemoApplication.java
├── config
│   └── SecurityConfig.java
├── entity
│   └── User.java
├── repository
│   └── UserRepository.java
├── security
│   ├── JwtTokenProvider.java
│   └── JwtAuthenticationFilter.java
├── service
│   └── UserService.java
└── web
    └── AuthController.java
```
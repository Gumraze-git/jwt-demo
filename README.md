# Gradle
## 전체 코드
```gradle
implementation 'io.jsonwebtoken:jjwt-api:0.11.5'
runtimeOnly   'io.jsonwebtoken:jjwt-impl:0.11.5'
runtimeOnly   'io.jsonwebtoken:jjwt-jackson:0.11.5'
```

## 코드 설명

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
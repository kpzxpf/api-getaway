# 🚪 LaborExchange API Gateway

<div align="center">

![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.2-brightgreen?style=for-the-badge&logo=spring)
![Spring Cloud Gateway](https://img.shields.io/badge/Spring_Cloud-Gateway-green?style=for-the-badge)
![JWT](https://img.shields.io/badge/JWT-Authentication-blue?style=for-the-badge)

**Centralized API Gateway & Routing**

</div>

---

## 📋 Overview

API Gateway serves as the single entry point for all client requests in the LaborExchange platform. It handles routing, authentication, CORS, and request/response logging.

### Key Features

✅ **Request Routing** - Routes to appropriate microservices  
✅ **JWT Validation** - Validates JWT tokens for protected routes  
✅ **CORS Handling** - Configurable cross-origin requests  
✅ **Request Logging** - Logs all incoming/outgoing requests  
✅ **Header Injection** - Adds user ID and role headers  
✅ **Load Balancing** - Distributes requests across service instances  

## 🏗️ Architecture

**Service:** Port 8080  

### System Flow

```
Client → API Gateway (8080) → Microservices
         ↓
    JWT Validation
         ↓
   Add X-User-Id & X-User-Role
```

### Routing Table

| Path | Target Service | Port | Protected |
|------|---------------|------|-----------|
| `/api/auth/**` | Auth Service | 8081 | Partial |
| `/api/users/**` | User Service | 8082 | Yes |
| `/api/roles/**` | User Service | 8082 | Yes |
| `/api/vacancies/**` | Vacancy Service | 8083 | Partial |
| `/api/companies/**` | Vacancy Service | 8083 | Yes |
| `/api/resumes/**` | Resume Service | 8084 | Yes |
| `/api/applications/**` | Application Service | 8085 | Yes |

## 🛠️ Technology Stack

| Component | Technology | Version |
|-----------|------------|---------|
| Framework | Spring Boot | 3.2.x |
| Gateway | Spring Cloud Gateway | 4.1.x |
| Language | Java | 17 |

## ⚙️ Configuration

### application.yaml

```yaml
server:
  port: 8080

spring:
  application:
    name: api-gateway
  
  cloud:
    gateway:
      # Global CORS Configuration
      globalcors:
        cors-configurations:
          '[/**]':
            allowed-origins:
              - "http://localhost:3000"
              - "https://laborexchange.com"
            allowed-methods:
              - GET
              - POST
              - PUT
              - DELETE
              - OPTIONS
            allowed-headers:
              - "*"
            allow-credentials: true
            max-age: 3600
      
      # Route Definitions
      routes:
        # Auth Service Routes
        - id: auth-service
          uri: http://localhost:8081
          predicates:
            - Path=/api/auth/**
          filters:
            - StripPrefix=0
        
        # User Service Routes
        - id: user-service
          uri: http://localhost:8082
          predicates:
            - Path=/api/users/**,/api/roles/**
          filters:
            - StripPrefix=0
            - JwtAuthenticationFilter
        
        # Vacancy Service Routes
        - id: vacancy-service
          uri: http://localhost:8083
          predicates:
            - Path=/api/vacancies/**,/api/companies/**
          filters:
            - StripPrefix=0
            - JwtAuthenticationFilter
        
        # Resume Service Routes
        - id: resume-service
          uri: http://localhost:8084
          predicates:
            - Path=/api/resumes/**
          filters:
            - StripPrefix=0
            - JwtAuthenticationFilter
        
        # Application Service Routes
        - id: application-service
          uri: http://localhost:8085
          predicates:
            - Path=/api/applications/**
          filters:
            - StripPrefix=0
            - JwtAuthenticationFilter
      
      # Default Filters
      default-filters:
        - DedupeResponseHeader=Access-Control-Allow-Origin
        - DedupeResponseHeader=Access-Control-Allow-Credentials

# JWT Configuration
jwt:
  secret: ${JWT_SECRET:myVerySecretKeyForJwtGenerationShouldBeLongEnough}

# Excluded URLs (no JWT required)
app:
  excluded-urls:
    - /api/auth/register
    - /api/auth/login
    - /api/vacancies  # Public vacancy listing
    - /actuator/**

logging:
  level:
    org.springframework.cloud.gateway: INFO
    com.vlz.laborexchange_apigateway: INFO
```

## 🔐 JWT Authentication Filter

### Filter Implementation

```java
@Component
@Slf4j
public class JwtAuthenticationFilter implements GatewayFilter, Ordered {
    
    @Value("${jwt.secret}")
    private String jwtSecret;
    
    @Value("#{'${app.excluded-urls}'.split(',')}")
    private List<String> excludedUrls;
    
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getPath().toString();
        
        // Skip validation for excluded URLs
        if (isExcluded(path)) {
            log.info("Skipping JWT validation for: {}", path);
            return chain.filter(exchange);
        }
        
        // Extract token from Authorization header
        String token = extractToken(request);
        
        if (token == null) {
            log.warn("Missing Authorization header for: {}", path);
            return onError(exchange, "Missing Authorization header", HttpStatus.UNAUTHORIZED);
        }
        
        try {
            // Validate and parse JWT
            Claims claims = Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
            
            // Extract user info
            Long userId = claims.get("userId", Long.class);
            String userRole = claims.get("role", String.class);
            
            log.info("Authenticated request: userId={}, role={}, path={}", 
                     userId, userRole, path);
            
            // Add user info to request headers
            ServerHttpRequest modifiedRequest = request.mutate()
                .header("X-User-Id", userId.toString())
                .header("X-User-Role", userRole)
                .build();
            
            return chain.filter(exchange.mutate().request(modifiedRequest).build());
            
        } catch (ExpiredJwtException e) {
            log.error("JWT token expired: {}", e.getMessage());
            return onError(exchange, "Token expired", HttpStatus.UNAUTHORIZED);
        } catch (Exception e) {
            log.error("JWT validation failed: {}", e.getMessage());
            return onError(exchange, "Invalid token", HttpStatus.UNAUTHORIZED);
        }
    }
    
    private String extractToken(ServerHttpRequest request) {
        List<String> headers = request.getHeaders().get(HttpHeaders.AUTHORIZATION);
        if (headers == null || headers.isEmpty()) {
            return null;
        }
        
        String authHeader = headers.get(0);
        if (authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        
        return null;
    }
    
    private boolean isExcluded(String path) {
        return excludedUrls.stream()
            .anyMatch(excluded -> path.startsWith(excluded.trim()));
    }
    
    private SecretKey getSigningKey() {
        byte[] keyBytes = jwtSecret.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }
    
    private Mono<Void> onError(ServerWebExchange exchange, 
                               String message, 
                               HttpStatus status) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);
        response.getHeaders().add(HttpHeaders.CONTENT_TYPE, "application/json");
        
        String errorResponse = String.format(
            "{\"error\":\"%s\",\"message\":\"%s\"}",
            status.getReasonPhrase(),
            message
        );
        
        DataBuffer buffer = response.bufferFactory()
            .wrap(errorResponse.getBytes(StandardCharsets.UTF_8));
        
        return response.writeWith(Mono.just(buffer));
    }
    
    @Override
    public int getOrder() {
        return -100; // High priority
    }
}
```

## 📝 Request/Response Logging

```java
@Component
@Slf4j
public class LoggingFilter implements GlobalFilter, Ordered {
    
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        
        log.info(">>> Request: {} {} from {}",
                 request.getMethod(),
                 request.getPath(),
                 request.getRemoteAddress());
        
        long startTime = System.currentTimeMillis();
        
        return chain.filter(exchange).then(Mono.fromRunnable(() -> {
            ServerHttpResponse response = exchange.getResponse();
            long duration = System.currentTimeMillis() - startTime;
            
            log.info("<<< Response: {} {} - Status: {} - Duration: {}ms",
                     request.getMethod(),
                     request.getPath(),
                     response.getStatusCode(),
                     duration);
        }));
    }
    
    @Override
    public int getOrder() {
        return -200; // Highest priority for logging
    }
}
```

## 🌐 CORS Configuration

### Custom CORS Configuration

```java
@Configuration
public class CorsConfig {
    
    @Bean
    public CorsWebFilter corsWebFilter() {
        CorsConfiguration config = new CorsConfiguration();
        
        // Allowed origins
        config.setAllowedOrigins(Arrays.asList(
            "http://localhost:3000",
            "https://laborexchange.com"
        ));
        
        // Allowed methods
        config.setAllowedMethods(Arrays.asList(
            "GET", "POST", "PUT", "DELETE", "OPTIONS"
        ));
        
        // Allowed headers
        config.setAllowedHeaders(Arrays.asList("*"));
        
        // Allow credentials
        config.setAllowCredentials(true);
        
        // Max age
        config.setMaxAge(3600L);
        
        UrlBasedCorsConfigurationSource source = 
            new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        
        return new CorsWebFilter(source);
    }
}
```

## 🔄 Load Balancing

### Service Discovery (Optional)

```yaml
spring:
  cloud:
    gateway:
      routes:
        - id: user-service
          uri: lb://user-service  # Load balanced
          predicates:
            - Path=/api/users/**
          filters:
            - StripPrefix=0
            - JwtAuthenticationFilter
    
    # Service Discovery with Consul/Eureka
    discovery:
      enabled: true
```

## 🧪 Testing

### Integration Tests

```java
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
class ApiGatewayIntegrationTest {
    
    @LocalServerPort
    private int port;
    
    @Autowired
    private WebTestClient webClient;
    
    @Test
    void authEndpoint_NoToken_Allowed() {
        webClient.post()
            .uri("/api/auth/login")
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue("{\"email\":\"test@example.com\",\"password\":\"password\"}")
            .exchange()
            .expectStatus().isOk();
    }
    
    @Test
    void protectedEndpoint_NoToken_Unauthorized() {
        webClient.get()
            .uri("/api/users/1")
            .exchange()
            .expectStatus().isUnauthorized();
    }
    
    @Test
    void protectedEndpoint_ValidToken_Success() {
        String token = generateValidToken();
        
        webClient.get()
            .uri("/api/users/1")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
            .exchange()
            .expectStatus().isOk();
    }
}
```

## 📊 Monitoring

```bash
# Health check
curl http://localhost:8080/actuator/health

# Gateway routes
curl http://localhost:8080/actuator/gateway/routes

# Metrics
curl http://localhost:8080/actuator/metrics/gateway.requests
```

## 🐛 Troubleshooting

### Common Issues

**1. CORS Error**
```yaml
# Add origin to allowed-origins
spring.cloud.gateway.globalcors.cors-configurations.[/**].allowed-origins:
  - http://localhost:3000
```

**2. JWT Validation Failed**
```bash
# Verify JWT secret matches Auth Service
jwt.secret=myVerySecretKeyForJwtGenerationShouldBeLongEnough
```

**3. Route Not Found**
```bash
# Check route configuration
curl http://localhost:8080/actuator/gateway/routes
```

## 🚀 Quick Start

```bash
# Set JWT secret
export JWT_SECRET=myVerySecretKeyForJwtGenerationShouldBeLongEnough

# Run gateway
./gradlew bootRun

# Test routing
curl http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password"}'
```

---

<div align="center">

**Made with ❤️ by the LaborExchange Team**

</div>

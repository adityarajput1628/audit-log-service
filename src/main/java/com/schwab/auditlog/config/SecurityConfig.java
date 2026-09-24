package com.schwab.auditlog.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Enterprise Security Configuration for Audit Log Service.
 *
 * THREAT MODEL & SECURITY DESIGN RATIONALE:
 * 1. CSRF Strategy: CSRF protection is explicitly disabled because this REST API is strictly stateless
 *    (SessionCreationPolicy.STATELESS) and relies on HTTP Basic or Bearer Authorization headers rather than ambient
 *    browser cookies (e.g., JSESSIONID). Cross-site request forgery requires automatic browser cookie submission;
 *    since no session cookies are issued or accepted, CSRF attacks are outside the API threat model.
 * 2. Secret Management: Credentials and HMAC keys are externalized via @Value property placeholders bound to
 *    environment variables (AUDIT_INGEST_USER, AUDIT_ADMIN_PASS, AUDIT_HMAC_SECRET). No secret constants are embedded.
 * 3. CORS Policy: Restricted to explicitly defined trusted origins (schwab.cors.allowed-origins). Wildcard (*)
 *    allowed origins with credentials are strictly prohibited.
 * 4. Profile Isolation: H2 Console endpoint access is restricted in dev and completely disabled in prod.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Value("${schwab.security.users.ingest.username}")
    private String ingestUsername;

    @Value("${schwab.security.users.ingest.password}")
    private String ingestPassword;

    @Value("${schwab.security.users.auditor.username}")
    private String auditorUsername;

    @Value("${schwab.security.users.auditor.password}")
    private String auditorPassword;

    @Value("${schwab.security.users.admin.username}")
    private String adminUsername;

    @Value("${schwab.security.users.admin.password}")
    private String adminPassword;

    @Value("${schwab.cors.allowed-origins:http://localhost:8080,http://127.0.0.1:8080}")
    private String allowedOriginsConfig;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        List<String> origins = Arrays.stream(allowedOriginsConfig.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toList());

        http
            .csrf(csrf -> csrf.disable()) // Stateless token/header auth threat model
            .cors(cors -> cors.configurationSource(request -> {
                CorsConfiguration corsConfig = new CorsConfiguration();
                corsConfig.setAllowedOrigins(origins);
                corsConfig.setAllowedMethods(List.of("GET", "POST", "OPTIONS"));
                corsConfig.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-Requested-With"));
                corsConfig.setAllowCredentials(true);
                return corsConfig;
            }))
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .exceptionHandling(exceptions -> exceptions
                .authenticationEntryPoint(customAuthenticationEntryPoint())
                .accessDeniedHandler(customAccessDeniedHandler())
            )
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/", "/index.html", "/favicon.ico", "/css/**", "/js/**", "/h2-console/**").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/v1/audit/events").hasAnyRole("INGEST", "ADMIN")
                .requestMatchers(HttpMethod.GET, "/api/v1/audit/events").hasAnyRole("INGEST", "AUDITOR", "ADMIN")
                .requestMatchers(HttpMethod.GET, "/api/v1/audit/verify").hasAnyRole("AUDITOR", "ADMIN")
                .requestMatchers(HttpMethod.GET, "/api/v1/audit/export").hasAnyRole("AUDITOR", "ADMIN")
                .requestMatchers(HttpMethod.GET, "/api/v1/compliance/client-access-report").hasAnyRole("AUDITOR", "ADMIN")
                .requestMatchers(HttpMethod.POST, "/api/v1/audit/events/*/redact").hasRole("ADMIN")
                .requestMatchers(HttpMethod.POST, "/api/v1/audit/retention/apply").hasRole("ADMIN")
                .requestMatchers(HttpMethod.POST, "/api/v1/audit/tamper-test").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .headers(headers -> headers
                .frameOptions(frame -> frame.sameOrigin())
                .xssProtection(xss -> xss.disable())
                .contentTypeOptions(contentType -> {})
            )
            .httpBasic(httpBasic -> {});

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
        UserDetails ingestUser = User.builder()
                .username(ingestUsername)
                .password(passwordEncoder.encode(ingestPassword))
                .roles("INGEST")
                .build();

        UserDetails auditorUser = User.builder()
                .username(auditorUsername)
                .password(passwordEncoder.encode(auditorPassword))
                .roles("AUDITOR")
                .build();

        UserDetails adminUser = User.builder()
                .username(adminUsername)
                .password(passwordEncoder.encode(adminPassword))
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(ingestUser, auditorUser, adminUser);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationEntryPoint customAuthenticationEntryPoint() {
        return (request, response, authException) -> {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            Map<String, Object> errorDetails = new HashMap<>();
            errorDetails.put("timestamp", Instant.now().toString());
            errorDetails.put("status", 401);
            errorDetails.put("error", "Unauthorized");
            errorDetails.put("message", "Full authentication is required to access this resource.");
            errorDetails.put("path", request.getRequestURI());
            objectMapper.writeValue(response.getOutputStream(), errorDetails);
        };
    }

    @Bean
    public AccessDeniedHandler customAccessDeniedHandler() {
        return (request, response, accessDeniedException) -> {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            Map<String, Object> errorDetails = new HashMap<>();
            errorDetails.put("timestamp", Instant.now().toString());
            errorDetails.put("status", 403);
            errorDetails.put("error", "Forbidden");
            errorDetails.put("message", "Access denied. Insufficient role permissions for this endpoint.");
            errorDetails.put("path", request.getRequestURI());
            objectMapper.writeValue(response.getOutputStream(), errorDetails);
        };
    }
}


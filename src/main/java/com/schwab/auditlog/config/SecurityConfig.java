package com.schwab.auditlog.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
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

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .cors(cors -> cors.configurationSource(request -> {
                var corsConfig = new org.springframework.web.cors.CorsConfiguration();
                corsConfig.setAllowedOrigins(List.of("http://localhost:8080", "http://127.0.0.1:8080"));
                corsConfig.setAllowedMethods(List.of("GET", "POST", "OPTIONS"));
                corsConfig.setAllowedHeaders(List.of("Authorization", "Content-Type"));
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
            .headers(headers -> headers.frameOptions(frame -> frame.sameOrigin()))
            .httpBasic(httpBasic -> {});

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
        UserDetails ingestUser = User.builder()
                .username("ingest")
                .password(passwordEncoder.encode("ingest123"))
                .roles("INGEST")
                .build();

        UserDetails auditorUser = User.builder()
                .username("auditor")
                .password(passwordEncoder.encode("auditor123"))
                .roles("AUDITOR")
                .build();

        UserDetails adminUser = User.builder()
                .username("admin")
                .password(passwordEncoder.encode("admin123"))
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

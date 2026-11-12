package com.yashsomani.secure_file_transfer;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.HeaderWriter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Spring Security configuration.
 *
 * <p>Enables method-level security infrastructure so that authorization
 * can be enforced declaratively with {@code @PreAuthorize} at the
 * service layer.</p>
 *
 * <p>CSRF is disabled for the REST API endpoints because this is a
 * same-origin browser application with session-based authentication.
 * The frontend never sends custom headers and the API is not exposed
 * to cross-origin requests in the current architecture. If the API
 * is ever opened to third-party clients, CSRF must be re-evaluated.</p>
 */
@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
            // CSRF disabled for REST API with same-origin session auth.
            // The frontend uses standard form login and same-origin AJAX.
            // If cross-origin API access is added, reconsider.
            .csrf(csrf -> csrf.disable())

            .sessionManagement(session -> session
                .sessionCreationPolicy(
                    SessionCreationPolicy.IF_REQUIRED
                )
                .maximumSessions(1)
                .maxSessionsPreventsLogin(false)
            )

            .authorizeHttpRequests(auth -> auth
                .requestMatchers(
                    "/",
                    "/index.html",
                    "/login.html",
                    "/register.html",
                    "/upload.html",
                    "/style.css",
                    "/api/hello",
                    "/api/auth/register",
                    "/api/auth/login"
                ).permitAll()

                .anyRequest().authenticated()
            )

            // Defense-in-depth security headers for the application.
            .headers(headers -> headers
                .addHeaderWriter(new HeaderWriter() {
                    @Override
                    public void writeHeaders(HttpServletRequest request,
                            HttpServletResponse response) {
                        response.setHeader("X-Content-Type-Options", "nosniff");
                        response.setHeader("X-Frame-Options", "DENY");
                        response.setHeader("Referrer-Policy",
                                "strict-origin-when-cross-origin");
                        response.setHeader("Permissions-Policy",
                                "camera=(), microphone=(), geolocation=()");

                        // Only advertise HTTPS expectations when the request itself is secure.
                        if (request.isSecure()) {
                            response.setHeader("Strict-Transport-Security",
                                    "max-age=31536000; includeSubDomains");
                        }
                    }
                })
            );

        return http.build();
    }
}
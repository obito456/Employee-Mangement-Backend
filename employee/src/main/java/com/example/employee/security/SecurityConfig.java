package com.example.employee.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // Define hardcoded user credentials
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("admin")
                               .password("{noop}admin123")
                               .roles("ADMIN")
                               .build();
        
        UserDetails user2 = User.withUsername("user")
                                .password("{noop}password")
                                .roles("USER")
                                .build();

        return new InMemoryUserDetailsManager(user, user2);
    }

    // Configure authorization rules
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/public/**").permitAll()
                .requestMatchers(HttpMethod.GET, "/api/employees").hasAnyRole("ADMIN", "USER") 
                .requestMatchers(HttpMethod.POST, "/api/**").hasRole("ADMIN") 
                .requestMatchers(HttpMethod.PUT, "/api/**").hasRole("ADMIN") 
                .requestMatchers(HttpMethod.DELETE, "/api/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .httpBasic();

        return http.build();
    }
}

package com.example.SpringSecurity.config.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        //Bearer<token>
        final String authHeader = request.getHeader("Authorization");
        String jwt = null;
        String email = null;

        if (authHeader != null || authHeader.startsWith("Bearer ")) {
            jwt = authHeader.substring(7);

            if (jwt == null || jwt.trim().isEmpty()){
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("Unauthorized: Missing or invalid token");
                return;
            }

            try {
                email = jwtUtil.extractEmail(jwt);
            }
            catch (Exception e){
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("Unauthorized: Invalid token");
                return;
            }
        }

    }
}

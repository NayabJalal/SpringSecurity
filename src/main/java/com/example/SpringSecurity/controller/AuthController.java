package com.example.SpringSecurity.controller;

import com.example.SpringSecurity.config.security.JwtUtil;
import com.example.SpringSecurity.dto.LoginUserDto;
import com.example.SpringSecurity.dto.RegisterUserDto;
import com.example.SpringSecurity.entity.Role;
import com.example.SpringSecurity.entity.User;
import com.example.SpringSecurity.service.RegisterUserService;
import com.example.SpringSecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {
    private final UserService userService;

    private final RegisterUserService registerUserService;

    private final JwtUtil jwtUtil;

    private final AuthenticationManager authenticationManager;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody  RegisterUserDto registerUserDto){
        User user = registerUserService.registerUser(registerUserDto.getEmail(), registerUserDto.getPassword());
        return ResponseEntity.ok(user);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginUserDto loginUserDto){
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginUserDto.getEmail(), loginUserDto.getPassword())
        );

        UserDetails userDetails = userService.loadUserByUsername(loginUserDto.getEmail());

        // GrantedAuthority uses Spring's "ROLE_*" prefix; Role enum names are USER, ADMIN.
        Set<Role> roles = userDetails.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .map(authority -> authority.startsWith("ROLE_")
                        ? authority.substring("ROLE_".length())
                        : authority)
                .map(Role::valueOf)
                .collect(Collectors.toSet());


        String token = jwtUtil.generateToken(userDetails.getUsername(),
                roles
        );

        return ResponseEntity.ok(token);
    }
}

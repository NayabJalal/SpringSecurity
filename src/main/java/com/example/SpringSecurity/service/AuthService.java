package com.example.SpringSecurity.service;

import com.example.SpringSecurity.dto.AuthenticationRequest;
import com.example.SpringSecurity.dto.AuthenticationResponse;
import com.example.SpringSecurity.dto.RegisterRequest;
import com.example.SpringSecurity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;

    public AuthenticationResponse authenticate(AuthenticationRequest request){
        return null;
    }

    public AuthenticationResponse register(RegisterRequest request){
        return null;
    }

}


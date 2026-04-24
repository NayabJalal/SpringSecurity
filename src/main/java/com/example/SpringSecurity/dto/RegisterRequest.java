package com.example.SpringSecurity.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RegisterRequest {

    @NotBlank(message = "Username is required!!")
    @Size(min = 3 , max = 20 ,message = "Username must be between 3 and 20 characters!!")
    private String username;

    @Email
    @Size(min = 3,max = 50)
    @NotBlank(message = "Email is required!!")
    private String email;

    @Size(min = 7,max = 20, message = "Password must be between 7 and 20 characters!!")
    @NotBlank(message = "Password must be Strong")
    private String password;

    private Set<String> roles;
}

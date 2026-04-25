package com.example.SpringSecurity.config.security;

import com.example.SpringSecurity.entity.Role;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

//fetch the payload back.
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private long expiration;

    public String generateToken(String email, Set<Role> roles){
        Map<String ,Object> claims = new HashMap<>();
        claims.put("email", email);
        claims.put("roles", roles.stream().map(Role::name).collect(Collectors.toSet()));
        return createToken(claims);
    }

    public String extractEmail(String token){
        return extractClaims(token).get("email").toString();
    }

    public Date extractExpiration(String token){
        return extractClaims(token).getExpiration();
    }

    public Boolean isTokenExpired(String token){
        return extractExpiration(token).before(new Date());
    }

    public boolean validateToken(String token, UserDetails userDetails){
        try {
            final String tokenEmail = extractEmail(token);
            boolean isTokenExpired = isTokenExpired(token);
            boolean userNameMatches = tokenEmail.equals(userDetails.getUsername());
            return userNameMatches && !isTokenExpired;
        }
        catch (Exception e){
            return false;
        }
    }

    public Claims extractClaims(String token) throws JwtException {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        }
        catch (SignatureException e){
            throw new JwtException("Invalid JWT signature: " + e.getMessage());
        }
        catch (MalformedJwtException e){
            throw new JwtException("Malformed JWT token: " + e.getMessage());
        }
        catch (ExpiredJwtException e){
            throw new JwtException("Expired JWT token: " + e.getMessage());
        }
        catch (UnsupportedJwtException e){
            throw new JwtException("Unsupported JWT token: " + e.getMessage());
        }
        catch (IllegalArgumentException e){
            throw new JwtException("JWT claims string is empty: " + e.getMessage());
        }
        catch (Exception e){
            throw new JwtException("Error parsing JWT token: " + e.getMessage());
        }
    }

    private SecretKey getSigningKey() {
        byte[] bytes = secret.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(bytes); //HMAC-SHA algorithm
    }
    private String createToken(Map<String , Object> claims){
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(claims.get("email").toString())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSigningKey())
                .compact();
    }
}

package com.rons.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
    private static final String SECRET_KEY = "6cf80f5042d1e694836fa44c9145649acb3fb79a550536b249b5315dda293ae8";

    public String generateToken(Map<String,Object> extraClaims, UserDetails userDetails){

        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                //Setting Expiration time as 22 HOURS
                .setExpiration(new Date(System.currentTimeMillis() + 1000*60*24 ))
                //Signing the key with HS256 algorithm
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                //To fill the details
                .compact();
    }

    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(), userDetails);
    }


    public boolean isTokenValid(String token, UserDetails userDetails){
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractClaim(token,Claims::getExpiration).before(new Date());

    }



    //We will use this function to generate SHA Key for the SECRET_KEY
    //Function return type would be key because the Jwts.setSigningKey takes argument as Key
    private Key getSignInKey(){
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }


    //IT is used to extract specific claim from a Jwt token
    public <T> T extractClaim(String token, Function<Claims, T>  claimsResolver){
        return claimsResolver.apply(
                Jwts.parserBuilder()
                        .setSigningKey(getSignInKey())
                        .build()
                        .parseClaimsJws(token)
                        .getBody()
        );
    }

    public String extractUsername(String token) {
        return extractClaim(token,Claims::getSubject);
    }

}

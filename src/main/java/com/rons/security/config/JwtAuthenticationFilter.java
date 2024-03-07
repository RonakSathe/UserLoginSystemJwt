package com.rons.security.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.CachingUserDetailsService;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private final JwtService jwtService;

    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {

        //We are extracting the authentication header from the request. Also called bearer token
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;

        //If we dont see any BEARER TOKEN, we will return so that it goes automatically to next filters in the chain
        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            filterChain.doFilter(request,response);
            return;
        }

        //If it exists, then

        //get jwt token in the jwt variable using substring function.
        jwt = authHeader.substring(7);

        //use the extractUsername implemented function from jwtservice file
        userEmail = jwtService.extractUsername(jwt);// TODO extract the userEmail from JWT TOKEN;

        //Checking if user is not authenticated
        //Using securitycontextholder becuase it holds the authentication details

        if(userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null){

            //Get userdetails from the database
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

            //check if user is valid or not
            if (jwtService.isTokenValid(jwt,userDetails)){

                //If valid, we create authentication Token
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );

                //
                authenticationToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );

                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
            //Always pass to next filter
            filterChain.doFilter(request,response);
        }

    }
}

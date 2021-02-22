package com.inclined.springsecurityjwt;

import com.inclined.springsecurityjwt.model.AuthenticationRequest;
import com.inclined.springsecurityjwt.model.AuthenticationResponse;
import com.inclined.springsecurityjwt.utils.JWTUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@RestController
public class HelloResource {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    @Qualifier("myUserDetailsService")
    UserDetailsService userDetailsService;

    @Autowired
    JWTUtil jwtUtil;

    @GetMapping("/hello")
    public String hello() {
        return "Hello world";
    }

    @PostMapping("/authenticate")
    public ResponseEntity<?> validateUser(@RequestBody AuthenticationRequest authenticationRequest) throws Exception {
        try{
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(), authenticationRequest.getPassword())
            );
        }catch(BadCredentialsException e) {
            throw new Exception("Incorrect username/password", e);
        }

        UserDetails userDetails = userDetailsService.loadUserByUsername(authenticationRequest.getUsername());
        String jwt = jwtUtil.generateToken(userDetails);
        return ResponseEntity.ok(new AuthenticationResponse(jwt));
    }
}

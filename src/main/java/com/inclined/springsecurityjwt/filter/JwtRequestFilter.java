package com.inclined.springsecurityjwt.filter;

import com.inclined.springsecurityjwt.utils.JWTUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    @Autowired
    JWTUtil jwtUtil;

    @Autowired
    @Qualifier("myUserDetailsService")
    UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
        throws ServletException, IOException {

        final String authorizationHeader = request.getHeader("Authorization");
        String username = null;
        String jwt = null;

        // getting the jwt and extract username from it using JWTUTIL
        if(authorizationHeader !=null && authorizationHeader.startsWith("Bearer ")){
            jwt = authorizationHeader.substring(7);
            username = jwtUtil.extractUsername(jwt);
        }

        //Check if username exists in jwt and check if context has already any authenticated user.
        if(username != null  && SecurityContextHolder.getContext().getAuthentication() == null) {

            // Below is what spring security would have done by default --------------------------

            //extract user from db using username-------------------------------------
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

            //validate the user with the jwt data.
            if(jwtUtil.validateToken(jwt, userDetails)){
                //if validated make a default token, then store it in SecurityContextHolder
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            }
        }

        // carry forward to next filter
        chain.doFilter(request,response);
    }

}

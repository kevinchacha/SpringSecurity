package com.cursos.api.springsecuritycourse.config_security.filter;
import com.cursos.api.springsecuritycourse.exception.ObjectNotFoundException;
import com.cursos.api.springsecuritycourse.persistence.entity.security.User;
import com.cursos.api.springsecuritycourse.service.UserService;
import com.cursos.api.springsecuritycourse.service.auth.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtService jwtService;

    @Autowired
    private UserService userService;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        System.out.println("Entrar en doFilterInternal");
        // get header http Authorization

        String authorizationHeader=request.getHeader("Authorization");

        if(!StringUtils.hasText(authorizationHeader) || !authorizationHeader.startsWith("Bearer ") ){
            filterChain.doFilter(request,response);
            return;
        }
        // get token JWT desde encabezado
        String jwt = authorizationHeader.substring(7);


        // get subject from token
        // this action valide the format of token , sign and expiration date
        String username= jwtService.extractUsername(jwt);
        User userDetails = userService.findOneByUsername(username)
                .orElseThrow(()->new ObjectNotFoundException("User not found "+username));

        // set objet authentication inside of security context holder
        UsernamePasswordAuthenticationToken authToken= new UsernamePasswordAuthenticationToken(
                username,null,userDetails.getAuthorities()
        );
        authToken.setDetails(new WebAuthenticationDetails(request));

        SecurityContextHolder.getContext().setAuthentication(authToken);

        // execute the filter register
        filterChain.doFilter(request,response);
    }
}

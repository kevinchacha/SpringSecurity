package com.cursos.api.springsecuritycourse.service.auth;
import com.cursos.api.springsecuritycourse.dto.RegisteredUser;
import com.cursos.api.springsecuritycourse.dto.SaveUser;
import com.cursos.api.springsecuritycourse.dto.auth.AuthenticationRequest;
import com.cursos.api.springsecuritycourse.dto.auth.AuthenticationResponse;
import com.cursos.api.springsecuritycourse.exception.ObjectNotFoundException;
import com.cursos.api.springsecuritycourse.persistence.entity.security.User;
import com.cursos.api.springsecuritycourse.service.UserService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Service;
import java.util.HashMap;
import java.util.Map;


@Service
public class AuthService {

    @Autowired
    private UserService userService;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private AuthenticationManager authenticationManager;

    public RegisteredUser registerOneCustomer(@Valid SaveUser newUser) {
        User user = userService.registerOneCustomer(newUser);
        RegisteredUser userDto = new RegisteredUser();
        userDto.setId(user.getId());
        userDto.setName(user.getName());
        userDto.setUsername(user.getUsername());
        userDto.setRole(user.getRole().getName());
        String jwt= jwtService.generateToken(user,generateExtraClaims(user));
        userDto.setJwt(jwt);
        return userDto;
    }

    private Map<String, Object> generateExtraClaims(User user) {
        Map<String, Object> extraClaims = new HashMap<>();
        extraClaims.put("name",user.getName());
        extraClaims.put("rol",user.getRole().getName());
        extraClaims.put("authorities",user.getAuthorities());
        extraClaims.put("username",user.getUsername());
        return extraClaims;
    }

    public AuthenticationResponse login(AuthenticationRequest authenticationRequest) {

        try {
            //generate structure
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    authenticationRequest.getUsername(),authenticationRequest.getPassword()
            );
            //do validaton
            authenticationManager.authenticate(authentication);
            //search details
            UserDetails user = userService.findOneByUsername(authenticationRequest.getUsername()).get();
            String jwt = jwtService.generateToken(user,generateExtraClaims((User)user));
            AuthenticationResponse authResponse= new AuthenticationResponse();
            authResponse.setJwt(jwt);
            return authResponse;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


    public boolean validateToken(String jwt) {
        //Validar header and payload
        try {
            jwtService.extractUsername(jwt);
            return true;
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return false;
        }
    }

    public User findLoggedInUser() {
        UsernamePasswordAuthenticationToken authToken = (UsernamePasswordAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        WebAuthenticationDetails details = (WebAuthenticationDetails) authToken.getDetails();
        System.out.println("----- authToken.getDetails --------");
        System.out.println("User IP: " + details.getRemoteAddress());
        System.out.println(" Session ID: " + details.getSessionId());
        String username = (String) authToken.getPrincipal();
        return userService.findOneByUsername(username)
                .orElseThrow(()->new ObjectNotFoundException("User not found "+username));
    }
}

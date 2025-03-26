package com.cursos.api.springsecuritycourse.config_security;
import com.cursos.api.springsecuritycourse.config_security.filter.JwtAuthenticationFilter;
import com.cursos.api.springsecuritycourse.persistence.utils.RoleEnum;
import com.cursos.api.springsecuritycourse.persistence.utils.RolePermissionEnum;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.RegexRequestMatcher;

@Configuration
@EnableWebSecurity //activa y configura componentes de spring security as authentication configuration
//@EnableMethodSecurity(prePostEnabled = true)
public class HttpSecurityConfig {

    // @Bean forma por la cual se crea una instancia y spring la guarda dentro de su contexto ,
    // y una vez creada se utiliza con Inyection of dependencias
    @Autowired
    private AuthenticationProvider daoauthenticationProvider;

    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @Autowired
    private AuthenticationEntryPoint authenticationEntryPoint;

    @Autowired
    private AccessDeniedHandler accessDeniedHandler;


    @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
         return http
                 .csrf(AbstractHttpConfigurer::disable)
                 .sessionManagement( sessMagConfig -> sessMagConfig.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                 .authenticationProvider(daoauthenticationProvider)
                 .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                 .authorizeHttpRequests(authReqConfig -> {
                     buildRequestMatchers(authReqConfig);
                 })
                 .exceptionHandling(exceptionConfi ->{
                     exceptionConfi.authenticationEntryPoint(authenticationEntryPoint);
                     exceptionConfi.accessDeniedHandler(accessDeniedHandler);
                 })
                 .build();

    }

    private static void buildRequestMatchers(AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry authReqConfig) {
        // Authorization de endpoints de products
        authReqConfig.requestMatchers(HttpMethod.GET,"/products")
                .hasAnyRole(RoleEnum.ADMINISTRATOR.name(), RoleEnum.ASSISTANT_ADMINISTRATOR.name());
//                .hasAuthority(RolePermission.READ_ALL_PRODUCTS.name());

//        authReqConfig.requestMatchers(HttpMethod.GET,"/products/{productId}")
//                .hasAnyRole(Role.ADMINISTRATOR.name(),Role.ASSISTANT_ADMINISTRATOR.name());
//                 .hasAuthority(RolePermission.READ_ONE_PRODUCT.name());

        //With regular expressions /products/{productId}
        authReqConfig.requestMatchers(RegexRequestMatcher.regexMatcher(HttpMethod.GET,"products/[1-9]*"))
                .hasAnyRole(RoleEnum.ADMINISTRATOR.name(), RoleEnum.ASSISTANT_ADMINISTRATOR.name());

        authReqConfig.requestMatchers(HttpMethod.POST,"/products")
                .hasRole(RoleEnum.ADMINISTRATOR.name());
//                .hasAuthority(RolePermission.CREATE_ONE_PRODUCT.name());

        authReqConfig.requestMatchers(HttpMethod.PUT,"/products/{productId}")
                .hasAnyRole(RoleEnum.ADMINISTRATOR.name(), RoleEnum.ASSISTANT_ADMINISTRATOR.name());



        //with expresion regular

//                .hasAuthority(RolePermission.UPDATE_ONE_PRODUCT.name());

        authReqConfig.requestMatchers(HttpMethod.PUT,"/products/{productId}/disabled")
                .hasRole(RoleEnum.ADMINISTRATOR.name());
//                .hasAuthority(RolePermission.DISABLE_ONE_PRODUCT.name());

        //Authorization de endpoints de categories

        authReqConfig.requestMatchers(HttpMethod.GET,"/categories")
                .hasAnyRole(RoleEnum.ADMINISTRATOR.name(), RoleEnum.ASSISTANT_ADMINISTRATOR.name());

//                .hasAuthority(RolePermission.READ_ALL_CATEGORIES.name());

        authReqConfig.requestMatchers(HttpMethod.GET,"/categories/{categoryId}")
                .hasAnyRole(RoleEnum.ADMINISTRATOR.name(), RoleEnum.ASSISTANT_ADMINISTRATOR.name());

//                .hasAuthority(RolePermission.READ_ONE_CATEGORY.name());

        authReqConfig.requestMatchers(HttpMethod.POST,"/categories")
                .hasRole(RoleEnum.ADMINISTRATOR.name());
//                .hasAuthority(RolePermission.CREATE_ONE_CATEGORY.name());

        authReqConfig.requestMatchers(HttpMethod.PUT,"/categories/{categoryId}")
                .hasAnyRole(RoleEnum.ADMINISTRATOR.name(), RoleEnum.ASSISTANT_ADMINISTRATOR.name());
//                .hasAuthority(RolePermission.UPDATE_ONE_CATEGORY.name());

        authReqConfig.requestMatchers(HttpMethod.PUT,"/categories/{categoryId}/disabled")
                .hasRole(RoleEnum.ADMINISTRATOR.name());

//                .hasAuthority(RolePermission.DISABLE_ONE_CATEGORY.name());

        authReqConfig.requestMatchers(HttpMethod.GET,"/auth/profile")
                        .hasAnyRole(RoleEnum.ADMINISTRATOR.name(), RoleEnum.ASSISTANT_ADMINISTRATOR.name(), RoleEnum.CUSTOMER.name());

        authReqConfig.requestMatchers(HttpMethod.GET,"/auth/validate")
                .hasAuthority(RolePermissionEnum.READ_MY_PROFILE.name());
        //Generics o publics

        authReqConfig.requestMatchers(HttpMethod.POST,"/customers").permitAll();
        authReqConfig.requestMatchers(HttpMethod.POST,"/auth/login").permitAll();
        authReqConfig.requestMatchers(HttpMethod.GET,"/auth/validate").permitAll();
        authReqConfig.anyRequest().authenticated();
    }


    private static void buildRequestMatchersbyMethods(AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry authReqConfig) {
        //Generics o publics

        authReqConfig.requestMatchers(HttpMethod.POST,"/customers").permitAll();
        authReqConfig.requestMatchers(HttpMethod.POST,"/auth/login").permitAll();
        authReqConfig.requestMatchers(HttpMethod.GET,"/auth/validate").permitAll();
        authReqConfig.anyRequest().authenticated();
    }
}

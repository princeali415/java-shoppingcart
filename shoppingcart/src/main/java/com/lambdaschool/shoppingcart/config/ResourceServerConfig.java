package com.lambdaschool.shoppingcart.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;

@Configuration
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter      // tells us who has access to what
{
    private static String RESOURCE_ID = "resource_id";

    @Override
    public void configure(ResourceServerSecurityConfigurer resources)
    {
        resources.resourceId(RESOURCE_ID)
            .stateless(false);
    }

    @Override
    public void configure (HttpSecurity http) throws Exception
    {
        // who has access to what   // This is where we spend most time setting up security
        http.authorizeRequests()
            .antMatchers("/",
                "/h2-console/**",
                "/swagger-resources/**",
                "/swagger-resource/**",
                "/swagger-ui.html",
                "/v2/api-docs",
                "/webjars/**",
                "/createnewuser",
                "/login")
            .permitAll()
            .antMatchers("/roles/**").hasAnyRole("ADMIN")
            .antMatchers("/products/**").hasAnyRole("ADMIN")
            .antMatchers("/users/**").hasAnyRole("ADMIN")
            .antMatchers("/carts/**").hasAnyRole("ADMIN", "USER")
            .antMatchers("/logout")
            .authenticated()
            .anyRequest().denyAll()
            .and()
            .exceptionHandling()
            .accessDeniedHandler(new OAuth2AccessDeniedHandler());

        http.csrf().disable();

        http.headers().frameOptions().disable(); // required by H2

        http.logout().disable();  // we are going to handle our own logout system
    }

}

package com.spring.security.springfundamentals.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Autowired
	private MyAuthenticationProvider authenticationProvider;

//	@Override
//	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//		BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
//		InMemoryUserDetailsManager userDetailsService = new InMemoryUserDetailsManager();
//		// create username and password
//		UserDetails user = User.withUsername("ali").password(passwordEncoder.encode("ali123")).authorities("read")
//				.build();
//		userDetailsService.createUser(user);
//		auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);
//
//	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(authenticationProvider);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.httpBasic();
//		http.formLogin();

		// allow authenticate requests
//		http.authorizeRequests().anyRequest().authenticated();
		http.authorizeRequests().antMatchers("/hello").authenticated();
		http.addFilterBefore(new SecurityFilter(), BasicAuthenticationFilter.class);
	}

//	@Bean
//	public AuthenticationManager authManager(HttpSecurity http, PasswordEncoder passwordEncoder,
//			UserDetailsService userDetailService) throws Exception {
//		return http.getSharedObject(AuthenticationManagerBuilder.class).authenticationProvider(authenticationProvider)
//				.build();
//	}
//
//	@Bean
//	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//		http.httpBasic();
//		http.authorizeRequests().anyRequest().authenticated();
//		return http.build();
//
//	}

}

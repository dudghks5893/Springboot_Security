package com.cos.security1.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터체인에 등록이 됩니다.
public class SecurityConfig extends WebSecurityConfigurerAdapter{
	
	// 해당 메서드의 리턴되는 오브젝트를 IoC로 등록해 준다.
	@Bean
	public BCryptPasswordEncoder encodePwd() {
		return new BCryptPasswordEncoder();
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable();
		http.authorizeRequests()
			.antMatchers("/user/**").authenticated() // 인증만 되면 들어갈 수 있는 주소!!
			.antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
			.antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
			.anyRequest().permitAll() // 위 주소를 제외한 나머지는 로그인 없이 접근 가능
			.and()
			.formLogin()
			.loginPage("/loginForm") // 시큐리티 로그인 폼을 사용하지 않고 내가 만든 로그인 폼 사용
			//.usernameParameter("바꾸고 싶은 파라메터네임") 기본으로 username 이다
			.loginProcessingUrl("/login") // /login 주소가 호출이 되면 시큐리티가 낚아채서 대신 로그인을 진행해 줍니다.
			.defaultSuccessUrl("/"); // 로그인 성공시 메인으로 이동 그리고 특정 페이지 요청해서 로그인하게 되면 특정 페이지로 이동(/user, /manager 등)
	}
	
}

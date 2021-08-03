package com.cos.security1.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepositoy;

@Controller // View를 리턴하겠다!!
public class IndexController {

	@Autowired
	private UserRepositoy userRepositoy;
	
	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	
    // OAuth 로그인 (구글)
    @GetMapping("/test/oauth/login")
	public @ResponseBody String testOAuthLogin(
			Authentication authentication,
			@AuthenticationPrincipal OAuth2User oauth) { // DI (의존성 주입)
		System.out.println("/test/oauth/login=============");
		OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal(); // Authentication 세션정보를 OAuth2User로 다운캐스팅
		System.out.println("/authentication : "+ oauth2User.getAttributes()); // OAuth2User로 프로필 받기
		
		System.out.println("oauth2User : "+oauth.getAttributes()); // @AuthenticationPrincipal 어노테이션 사용으로 받기
		return "OAuth세션 정보 확인하기";
	}
	// 일반 로그인
	@GetMapping("/test/login")
	public @ResponseBody String testLogin(
			Authentication authentication,
			@AuthenticationPrincipal PrincipalDetails userDetails) { // DI (의존성 주입)
		System.out.println("/test/login=============");
		PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal(); // Authentication을 UserDetails로 다운캐스팅 (PrincipalDetails클레스는 지금 UserDetails를 implement하고 있다.)
		System.out.println("/authentication : "+ principalDetails.getUser()); // UserDetails 로 프로필 받기 (PrincipalDetails클레스는 지금 UserDetails를 implement하고 있다.)
		
		System.out.println("userDetails : "+userDetails.getUser()); // @AuthenticationPrincipal 어노테이션 사용으로 받기
		return "세션 정보 확인하기";
	}
	
		// localhost:8000/
		// localhost:8000
	@GetMapping({"","/"})
	public String index() {
		// 머스테치 기본폴더 src/main/resources/
		// 뷰리졸버 설정 : templates (prefix), .mustache (suffix) 생략가능!!
		/*
		 application.yml 파일에 생략 가능
		  	mvc:
    		  view:
      		    prefix: /templates/
      		    suffix: .mustache 
		 */
		return "index"; // src/main/resources/templates/index.mustache
	}
	
	// OAuth 로그인을 해도 PrincipalDetails 타입으로 받을 수 있고
	// 일반 로그인을 해도 PrincipalDetails 타입으로 받을 수 있다.
	@GetMapping("/user")
	public @ResponseBody String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
		System.out.println("principalDetails : "+principalDetails.getUser());
		return "user";
	}
	
	@GetMapping("/admin")
	public @ResponseBody String admin() {
		return "admin";
	}
	
	@GetMapping("/manager")
	public @ResponseBody String manager() {
		return "manager";
	}
	
	// 스프링시큐리티가 해당주소를 낚아 채버림 - SecurityConfig 파일 생성 후 작동안함.
	@GetMapping("/loginForm")
	public String loginForm() {
		return "loginForm";
	}
	
	@GetMapping("/joinForm")
	public String joinForm() {
		return "joinForm";
	}
	
	@PostMapping("/join")
	public String join(User user) {
		//System.out.println(user);
		user.setRole("ROLE_USER");
		// save하면 회원가입 잘됨. 비밀번호 : 1234 => 시큐리티로 로그인을 할 수 없음. 
		// 이유는 패스워드가 암호화가 안되었기 때문 그러니 암호화 시켜줌
		String rawPassword = user.getPassword();
		String encPassword = bCryptPasswordEncoder.encode(rawPassword);
		user.setPassword(encPassword);
		
		userRepositoy.save(user); 
		return "redirect:/loginForm";
	}
	
	@Secured("ROLE_ADMIN") // 한개만 권한 줄때 사용
	@GetMapping("/info")
	public @ResponseBody String info() {
		return "개인정보";
	}
	
	@PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')") // 여러개 권한 주기
	@GetMapping("/data")
	public @ResponseBody String data() {
		return "데이터";
	}
	
}

package com.cos.security1.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepositoy;

@Controller // View를 리턴하겠다!!
public class IndexController {

	@Autowired
	private UserRepositoy userRepositoy;
	
	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	
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
	
	@GetMapping("/user")
	public @ResponseBody String user() {
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
	
	
}

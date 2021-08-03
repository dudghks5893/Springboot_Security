package com.cos.security1.config.auth;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import com.cos.security1.model.User;

import lombok.Data;

// 시큐리티가 /login 주소 요청이 오면 낚아채서 로그인을 진행 시킨다.
// 로그인 진행이 완료가 되면 시큐리티 session을 만들어 준다. (Security ContextHolder)
// 오브젝트 타입=> Authentication 타입 객체
// Authentication 안에 User 정보가 있어야 됨.
// User 오브젝트 타입 => UserDetails 타입 객체

// Security Session => Authentication => UserDetails(PrincipalDetails)

@Data
public class PrincipalDetails implements UserDetails, OAuth2User{
	
	private User user; // 콤포지션
	private Map<String, Object> attributes;
	
	// 일반 로그인
	public PrincipalDetails(User user) {
		this.user = user;
	}
	
	// OAuth 로그인
	public PrincipalDetails(User user, Map<String, Object> attributes) {
		this.user = user;
		this.attributes = attributes;
	}
	// 해당 User의 권한을 리턴하는 곳!!
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		Collection<GrantedAuthority> collect = new ArrayList<>(); // ArrayList는 Collection의 자식이다.
		collect.add(new GrantedAuthority() {
			
			@Override
			public String getAuthority() {
				return user.getRole();
			}
		});
		return collect;
	}

	@Override
	public String getPassword() {
		return user.getPassword();
	}

	@Override
	public String getUsername() {
		return user.getUsername();
	}
	// 계정 만료 (true = 만료 아님)
	@Override
	public boolean isAccountNonExpired() {
		return true; // 만료 안됨
	}
	// 계정 잠금 여부
	@Override
	public boolean isAccountNonLocked() {
		return true; // 안 잠겼음
	}
	// 비밀번호가 기간이 지났니 오래사용한거 아니니 여부
	@Override
	public boolean isCredentialsNonExpired() {
		return true; // 오래 안됨
	}
	// 계정 활성화 여부
	@Override
	public boolean isEnabled() {
		
		// 우리 사이트!! 1년동안 회원이 로그인을 안하면 휴먼 계정으로 하기로 함.
		// 현재시간 - 로긴시간 => 1년을 초과하면 return false;
		
		return true; // 활성화
	}
	@Override
	public Map<String, Object> getAttributes() {
		return attributes;
	}
	@Override
	public String getName() {
		return null;
	}
	
}

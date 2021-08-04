package com.cos.security1.config.oauth.provider;

public interface OAuth2UserInfo {
	String getProviderId(); // 구글 sub= 112188858007110237324, 페이스북 id=1800128786857677
	String getProvider(); // google, facebook
	String getEmail();
	String getName();
}

package com.cos.security1.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

import com.cos.security1.config.oauth.PrincipalOauth2UserService;


@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터체인에 등록이 됨
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true) // secured 어노테이션 활성화, preAuthorize, postAuthorize 어노테이션 활성화
public class SecurityConfig {
	
// @Autowired의 객체 생성 주입 방식
//	@Autowired
//	private PrincipalOauth2UserService principalOauth2UserService;
	
//	 @Bean어노테이션은 해당 메서드의 리턴되는 오브젝트를 IoC로 등록해준다.
//	@Bean
//	public BCryptPasswordEncoder encodePwd() {
//		return new BCryptPasswordEncoder();
//	}
	
	
	// @Autowired의 생성자 주입 방식
	private PrincipalOauth2UserService principalOauth2UserService;
	
	@Autowired
	public SecurityConfig(PrincipalOauth2UserService principalOauth2UserService) {
		this.principalOauth2UserService = principalOauth2UserService;
	}

	@Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeRequests()
                .antMatchers("/user/**").authenticated() // 인증만 되면 들어갈 수 있는 주소
                .antMatchers("/manager/**").access("hasAnyRole('ROLE_MANAGER','ROLE_ADMIN')")
                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll()
                .and()
                .formLogin()
                .loginPage("/loginForm")
                .loginProcessingUrl("/login") // /login 주소가 호출이 되면 시큐리티가 낚아채서 대신 로그인을 진행해줌
        		.defaultSuccessUrl("/")
        		.and()
        		.oauth2Login()
        		.loginPage("/loginForm") 
        		.userInfoEndpoint()		//oauth2Login에 성공하면 principalOauth2UserService에서 설정을 진행하겠다는 의미
        		.userService(principalOauth2UserService); // 구글 로그인이 완료된 뒤의 후처리가 필요함. 1. 코드받기(인증), 2. 엑세스토큰, 3. 사용자프로필 정보를 가져오고 4. 그 정보를 토대로 회원가입을 자동으로 진행시키기도 함 
        return http.build();							  // Tip. 구글로그인이 완료되면 코드를 받는게 아닌, (엑세스토큰 + 사용자프로필정보를 받음)
    }
}

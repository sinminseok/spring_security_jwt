package security.account.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import security.account.filter.CustomLoginAuthenticationFilter;
import security.account.filter.JwtAuthenticationFilter;
import security.account.handler.LoginFailureHandler;
import security.account.handler.LoginSuccessHandler;
import security.account.repository.UserRepository;
import security.account.service.JwtService;
import security.account.service.LoginService;

/**
 * 인증은 CustomJsonUsernamePasswordAuthenticationFilter에서 authenticate()로 인증된 사용자로 처리
 * JwtAuthenticationProcessingFilter는 AccessToken, RefreshToken 재발급
 */
@Configuration
@EnableWebSecurity // @EnableWebSecurity 어노테이션을 붙여야 Spring Security 기능을 사용할 수 있다.
@RequiredArgsConstructor
public class SecurityConfig {

    private final LoginService loginService;
    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final ObjectMapper objectMapper;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .formLogin((formLogin) -> formLogin.disable()) // Spring Security 에서는 아무 설정을 하지 않으면 기본 FormLogin 형식의 로그인을 제공한다
                .httpBasic((httpBasic) -> httpBasic.disable()) // JWT 토큰을 사용한 로그인 방식이기 때문에 httpBasic disable 로 설정
                .csrf((csrfConfig) -> csrfConfig.disable()) // 서버에 인증 정보를 저장하지 않고, 요청 시 인증 정보를 담아서 요청 하므로 보안 기능인 csrf 불필요
                .httpBasic((httpBasic) -> httpBasic.disable())
                .headers((headerConfig) ->
                        headerConfig.frameOptions(frameOptionsConfig ->
                                frameOptionsConfig.disable()
                        )
                )
                // 세션 사용 x
                .sessionManagement((sessionManagement) -> sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/sign-up").permitAll()
                        .anyRequest().authenticated()
                );


        // 일반 로그인 시 customJsonUsernamePasswordAuthenticationFilter 동작

        /**
         * addFilterAfter(A, B) B 필터 이후에 A 필터 동작
         * 원래 스프링 시큐리티 필터 동작 순서가 LogoutFilter 이후에 로그인 동작 필터가 동작한다.
         *
         * addFilterBefore(A, B) B 필터 이잔에 A 필터 동작
         * Json 로그인 필터가 동작하기전 JWT 인증 필터 동작
         *
         * LogoutFilter -> jwtAuthenticationFilter -> customJsonUsernamePasswordAuthenticationFilter
         */
        http.addFilterAfter(customLoginAuthenticationFilter(), LogoutFilter.class);
        http.addFilterBefore(jwtAuthenticationFilter(), CustomLoginAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public CustomLoginAuthenticationFilter customLoginAuthenticationFilter() {
        //CustomJsonUsernamePasswordAuthenticationFilter 에서 인증할 객체(Authentication) 생성
        CustomLoginAuthenticationFilter customJsonUsernamePasswordLoginFilter
                = new CustomLoginAuthenticationFilter(objectMapper);

        //일반 로그인 인증 로직
        customJsonUsernamePasswordLoginFilter.setAuthenticationManager(authenticationManager());

        customJsonUsernamePasswordLoginFilter.setAuthenticationSuccessHandler(loginSuccessHandler());
        customJsonUsernamePasswordLoginFilter.setAuthenticationFailureHandler(loginFailureHandler());
        return customJsonUsernamePasswordLoginFilter;
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        //비밀번호 인코딩
        provider.setPasswordEncoder(passwordEncoder());
        //loginService loadUserByUsername 호출 이때 DaoAuthenticationProvider 가 username 을 꺼내서 loadUserByUsername 을 호출
        provider.setUserDetailsService(loginService);
        // loadUserByUsername 에서 전달받은 UserDetails 에서 password를 추출해 내부의 PasswordEncoder 에서 password 가 일치하는지 검증을 수행
        return new ProviderManager(provider);
    }

    // jwt 인증필터 빈 등록
    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(jwtService, userRepository);
        return jwtAuthenticationFilter;
    }

     // 로그인 성공 시 호출되는 LoginSuccessHandler 빈 등록

    @Bean
    public LoginSuccessHandler loginSuccessHandler() {
        return new LoginSuccessHandler(jwtService, userRepository);
    }

     // 로그인 실패 시 호출되는 LoginFailureHandler 빈 등록
    @Bean
    public LoginFailureHandler loginFailureHandler() {
        return new LoginFailureHandler();
    }

    // 패스워드 인코딩을 위한 기능 빈 등록
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}

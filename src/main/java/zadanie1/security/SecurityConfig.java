package zadanie1.security;
import org.springframework.context.annotation.*; import org.springframework.http.HttpMethod; import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity; import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy; import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder; import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.*; import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter; import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
@Configuration @EnableWebSecurity @EnableMethodSecurity
public class SecurityConfig {
 @Bean PasswordEncoder passwordEncoder(){return new BCryptPasswordEncoder();}
 @Bean SecurityFilterChain filterChain(HttpSecurity http,JwtAuthenticationFilter jwt,RestAuthenticationEntryPoint entry,RestAccessDeniedHandler denied)throws Exception{
  http.csrf(c->c.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).ignoringRequestMatchers("/auth/**","/api/auth/**"))
   .sessionManagement(s->s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
   .authorizeHttpRequests(a->a.requestMatchers("/auth/login","/auth/register","/auth/refresh","/auth/csrf","/api/auth/csrf").permitAll()
    .requestMatchers(HttpMethod.POST,"/api/users").denyAll()
    .requestMatchers(HttpMethod.POST,"/api/users/**","/api/meters/**","/api/premises/**").hasRole("ADMIN")
    .requestMatchers(HttpMethod.PATCH,"/api/users/**","/api/meters/**","/api/premises/**").hasRole("ADMIN")
    .requestMatchers(HttpMethod.DELETE,"/api/users/**","/api/meters/**","/api/premises/**").hasRole("ADMIN")
    .requestMatchers(HttpMethod.POST,"/api/business/meters/*/readings").hasAnyRole("USER","ADMIN")
    .requestMatchers(HttpMethod.POST,"/api/business/readings/*/approve").hasRole("ADMIN")
    .requestMatchers(HttpMethod.POST,"/api/business/charges/*/pay").hasAnyRole("USER","ADMIN")
    .requestMatchers(HttpMethod.POST,"/api/business/premises/*/transfer/*").hasRole("ADMIN")
    .requestMatchers(HttpMethod.GET,"/api/business/reports/*").hasRole("ADMIN").anyRequest().authenticated())
   .httpBasic(b->b.disable()).formLogin(f->f.disable()).exceptionHandling(e->e.authenticationEntryPoint(entry).accessDeniedHandler(denied))
   .addFilterBefore(jwt,UsernamePasswordAuthenticationFilter.class); return http.build();
 }
}

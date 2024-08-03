package rtg.learning.spring_security.jwt;

import static org.springframework.security.config.Customizer.withDefaults;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
public class JwtSecurityConfiguration {
	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//		http.authorizeHttpRequests((requests) -> requests.anyRequest().authenticated());
//		http.formLogin(withDefaults());
//		http.httpBasic(withDefaults());
//		return http.build();

		http.authorizeHttpRequests(auth -> {
			auth.anyRequest().authenticated();
		});
		http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
		http.formLogin();
//		http.httpBasic();
//		http.csrf().disable();

		http.httpBasic(withDefaults());
		http.csrf(AbstractHttpConfigurer::disable);

		http.headers().frameOptions().sameOrigin();

		// HERE, WE'RE CONFIGURING THE OAUTH2 RESOURCE SERVER.
//		THIS RESOURCE SERVER, WHEN IT RECEIVES A JWT TOKEN, IT NEEDS TO DECODE IT
//		AND TO DECODE, IT NEEDS A DECODER I.E JWTDECODER
		http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);

		return http.build();

	}

	@Bean
	public DataSource dataSource() {
		return new EmbeddedDatabaseBuilder().setType(EmbeddedDatabaseType.H2)
				.addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION).build();
	}

	@Bean
	public UserDetailsService userDetailService(DataSource dataSource) {
		var user = User.withUsername("coderaider")
//			.password("{noop}dummy")
				.password("dummy").passwordEncoder(str -> passwordEncoder().encode(str)).roles("USER").build();

		var admin = User.withUsername("admin")
//				.password("{noop}dummy")
				.password("dummy").passwordEncoder(str -> passwordEncoder().encode(str)).roles("ADMIN").build();

		var jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
		jdbcUserDetailsManager.createUser(user);
		jdbcUserDetailsManager.createUser(admin);

		return jdbcUserDetailsManager;
	}

	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	// 1 . create key pair
	@Bean
	public KeyPair keyPair() {
		try {
			var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			return keyPairGenerator.generateKeyPair();
		} catch (Exception ex) {
			throw new RuntimeException(ex);
		}
	}

	// 2. create RSA Key Object using Key Pair created in method 1(above method)
	@Bean
	public RSAKey rsaKey(KeyPair keyPair) {
		return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic()).privateKey(keyPair.getPrivate())
				.keyID(UUID.randomUUID().toString()).build();
	}

	// 3. creating JWK Source (json web key source)
//	a) creating JWKSet using the RSA Key object created in method2
//	b) creating JWKSource using JWKSet 
	@Bean
	public JWKSource<SecurityContext> jwkSource(RSAKey rsaKey) {
		var jwkSet = new JWKSet(rsaKey);

//		var jwkSource=new JWKSource() {
//
//			@Override
//			public List get(JWKSelector jwkSelector, SecurityContext context) throws KeySourceException {
//				return jwkSelector.select(jwkSet);
//			}
//			
//		};
//		return jwkSource;

		return (jwkSelector, context) -> jwkSelector.select(jwkSet);
	}
	
	// 4. JwtDecoder used RSA Key
	@Bean
	public JwtDecoder jwtDecoder(RSAKey rsaKey) throws JOSEException {
		return NimbusJwtDecoder.withPublicKey(rsaKey.toRSAPublicKey()).build();
	}
	
	@Bean
	public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
		return new NimbusJwtEncoder(jwkSource);
	}
}

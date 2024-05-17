/**
 * Copyright 2024 DEV4Sep
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.dev4sep.base.config;

import com.dev4sep.base.role.Role;
import com.dev4sep.base.user.User;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.AuditorAware;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;

import javax.sql.DataSource;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.util.stream.Collectors;

/**
 * @author YISivlay
 */
@Configuration
@RequiredArgsConstructor
public class AppConfig {

    @Bean
    public JdbcUserDetailsManager userDetailsService(DataSource dataSource) {
        var userManager = new JdbcUserDetailsManager(dataSource);
        List<Role> roles = new ArrayList<>();
        roles.add(Role.builder().name("ADMIN").build());
        UserDetails userDetails = User.builder()
                .username("system")
                .password(passwordEncoder().encode("password"))
                .roles(roles)
                .build();

        userManager.createUser(userDetails);
        return userManager;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public static OAuth2TokenGenerator<?> tokenGenerator() {
        var jwtGenerator = new JwtGenerator(new NimbusJwtEncoder(jwkSource()));
        jwtGenerator.setJwtCustomizer(jwtCustomizer());
        var refreshTokenOAuth2TokenGenerator = new OAuth2RefreshTokenGeneratorConfig();
        return new DelegatingOAuth2TokenGenerator(jwtGenerator, refreshTokenOAuth2TokenGenerator);
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        var registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
        if (Objects.isNull(registeredClientRepository.findByClientId("public-client"))) {
            var publicClient = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("public-client")
                    .clientSecret("{noop}secret")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .redirectUri("http://127.0.0.1:8080/login/oauth2/code/public-client")
                    .postLogoutRedirectUri("http://127.0.0.1:8080/")
                    .scope(OidcScopes.OPENID)
                    .scope(OidcScopes.PROFILE)
                    .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                    .build();
            registeredClientRepository.save(publicClient);
        }

        return registeredClientRepository;
    }

    @Bean
    public AuditorAware<Long> auditorAware() {
        return new AuditAwareConfig();
    }

    @Bean
    public static JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRSAKeys();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        RSAKey build = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();

        JWKSet jwkSet = new JWKSet(build);
        return new ImmutableJWKSet<>(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    private static KeyPair generateRSAKeys() {
        KeyPair keyPair;

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception exception) {
            throw new RuntimeException("failed to create keypair!");
        }

        return keyPair;
    }

    public static OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return context -> {
            if (context.getTokenType().getValue().equals(OidcParameterNames.ID_TOKEN)) {
                Authentication principle = context.getPrincipal();
                Set<String> authorities = principle.getAuthorities()
                        .stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toSet());

                context.getClaims().claim("authorities", authorities);
            }
        };
    }


}

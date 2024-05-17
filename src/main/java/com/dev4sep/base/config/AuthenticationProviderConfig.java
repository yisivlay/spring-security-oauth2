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

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

/**
 * @author YISivlay
 */
@RequiredArgsConstructor
public class AuthenticationProviderConfig implements AuthenticationProvider {

    private final RegisteredClientRepository registeredClientRepository;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        OAuth2ClientAuthenticationTokenConfig oAuth2ClientAuthenticationTokenConfig = (OAuth2ClientAuthenticationTokenConfig) authentication;
        if (!ClientAuthenticationMethod.NONE.equals(oAuth2ClientAuthenticationTokenConfig.getClientAuthenticationMethod())) {
            return null;
        }
        String clientId = oAuth2ClientAuthenticationTokenConfig.getPrincipal().toString();
        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT, "Client is invalid", null)
            );
        }

        if (!registeredClient.getClientAuthenticationMethods().contains(oAuth2ClientAuthenticationTokenConfig.getClientAuthenticationMethod())) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT, "Authentication method is not register with client", null)
            );
        }

        return new OAuth2ClientAuthenticationTokenConfig(registeredClient);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return false;
    }
}

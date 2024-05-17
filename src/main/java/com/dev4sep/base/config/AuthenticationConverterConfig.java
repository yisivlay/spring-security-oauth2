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

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

/**
 * @author YISivlay
 */
public class AuthenticationConverterConfig implements AuthenticationConverter {

    @Override
    public Authentication convert(HttpServletRequest request) {

        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        if (!grantType.equals(AuthorizationGrantType.REFRESH_TOKEN.getValue())) {
            return null;
        }
        String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
        if (!StringUtils.hasText(clientId)) {
            return null;
        }
        return new OAuth2ClientAuthenticationTokenConfig(clientId);
    }
}

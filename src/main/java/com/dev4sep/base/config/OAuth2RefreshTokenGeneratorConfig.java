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
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import java.time.Instant;
import java.util.Base64;

/**
 * @author YISivlay
 */
@RequiredArgsConstructor
public final class OAuth2RefreshTokenGeneratorConfig implements OAuth2TokenGenerator<OAuth2RefreshToken> {

    private final StringKeyGenerator refreshTokenGenerator = new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);

    @Override
    public OAuth2RefreshToken generate(OAuth2TokenContext context) {
        if (!OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) {
            return null;
        } else {
            Instant issuedAt = Instant.now();
            Instant expiredAt = issuedAt.plus(context.getRegisteredClient().getTokenSettings().getRefreshTokenTimeToLive());
            return new OAuth2RefreshToken(this.refreshTokenGenerator.generateKey(), issuedAt, expiredAt);
        }
    }
}

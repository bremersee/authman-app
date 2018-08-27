/*
 * Copyright 2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.bremersee.authman.security.oauth2.provider.token.store;

import java.util.Collection;
import java.util.List;
import javax.validation.constraints.NotNull;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bremersee.authman.domain.OAuth2AccessTokenRepository;
import org.bremersee.authman.domain.OAuth2AuthenticationKey;
import org.bremersee.authman.domain.OAuth2RefreshTokenRepository;
import org.springframework.data.util.CastUtils;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.endpoint.TokenEndpoint;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.util.SerializationUtils;
import org.springframework.util.StringUtils;

/**
 * @author Christian Bremer
 */
@RequiredArgsConstructor
@Slf4j
public class OAuth2TokenStore implements TokenStore {

  @NonNull
  private final OAuth2AccessTokenRepository accessTokenRepository;

  @NonNull
  private final OAuth2RefreshTokenRepository refreshTokenRepository;

  @Override
  public OAuth2AccessToken getAccessToken(final OAuth2Authentication authentication) {

    if (authentication == null || authentication.getOAuth2Request() == null) {
      return null;
    }
    try {
      final OAuth2AuthenticationKey authKey = new OAuth2AuthenticationKey(authentication);
      log.debug("Getting access token by authentication: {}", authKey);
      final List<org.bremersee.authman.domain.OAuth2AccessToken> accessToken;
      if (StringUtils.hasText(authKey.getUserName())) {
        accessToken = accessTokenRepository
            .findFirstByUserNameAndClientIdAndScopesOrderByExpirationAsc(
                authKey.getUserName(), authKey.getClientId(), authKey.getScopes());
      } else {
        accessToken = accessTokenRepository
            .findFirstByUserNameIsNullAndClientIdAndScopesOrderByExpirationAsc(
                authKey.getClientId(), authKey.getScopes());
      }
      log.info("Found access token by authentication = {}", accessToken);
      return accessToken.isEmpty() ? null : accessToken.get(0);

    } catch (RuntimeException re) {
      log.error("Getting token failed.", re);
      throw re;
    }
  }

  @Override
  public void storeAccessToken(
      @NotNull final OAuth2AccessToken token,
      @NotNull final OAuth2Authentication authentication) {

    org.bremersee.authman.domain.OAuth2AccessToken accessTokenEntity = accessTokenRepository
        .findByValue(token.getValue())
        .orElse(new org.bremersee.authman.domain.OAuth2AccessToken());
    final OAuth2AuthenticationKey authKey = new OAuth2AuthenticationKey(authentication);
    accessTokenEntity.setUserName(authKey.getUserName());
    accessTokenEntity.setClientId(authKey.getClientId());
    accessTokenEntity.setScopes(authKey.getScopes());
    accessTokenEntity.setAuthentication(SerializationUtils.serialize(authentication));

    accessTokenEntity.setValue(token.getValue());
    accessTokenEntity.setExpiration(token.getExpiration());
    accessTokenEntity.setTokenType(token.getTokenType());
    if (token.getRefreshToken() != null) {
      accessTokenEntity.setRefreshTokenValue(token.getRefreshToken().getValue());
    } else {
      accessTokenEntity.setRefreshTokenValue(null);
    }
    accessTokenEntity.getScope().clear();
    if (token.getScope() != null) {
      accessTokenEntity.getScope().addAll(token.getScope());
    }
    accessTokenEntity.getAdditionalInformation().clear();
    if (token.getAdditionalInformation() != null) {
      accessTokenEntity.getAdditionalInformation().putAll(token.getAdditionalInformation());
    }

    log.debug("Storing access token {}", accessTokenEntity);
    accessTokenRepository.save(accessTokenEntity);
  }

  @Override
  public OAuth2AccessToken readAccessToken(@NotNull final String tokenValue) {

    log.debug("Reading access token by token value ...");
    return accessTokenRepository.findByValue(tokenValue).orElse(null);
  }

  @Override
  public void removeAccessToken(final OAuth2AccessToken token) {

    log.debug("Removing access token ...");
    if (token != null) {
      removeAccessToken(token.getValue());
    }
  }

  private void removeAccessToken(final String tokenValue) {

    log.debug("Removing access token by value...");
    if (tokenValue != null) {
      accessTokenRepository.deleteByValue(tokenValue);
    }
  }

  @Override
  public OAuth2Authentication readAuthentication(@NotNull final OAuth2AccessToken token) {
    log.debug("Reading authentication by token ...");
    return readAuthentication(token.getValue());
  }

  @Override
  public OAuth2Authentication readAuthentication(@NotNull final String token) {
    log.debug("Reading authentication by token value ...");
    return accessTokenRepository.findByValue(token).map(
        oAuth2AccessToken -> (OAuth2Authentication) SerializationUtils.deserialize(
            oAuth2AccessToken.getAuthentication()))
        .orElse(null);
  }


  @Override
  public void storeRefreshToken(
      @NotNull final OAuth2RefreshToken refreshToken,
      @NotNull final OAuth2Authentication authentication) {

    org.bremersee.authman.domain.OAuth2RefreshToken tokenEntity = refreshTokenRepository
        .findByValue(refreshToken.getValue())
        .orElse(new org.bremersee.authman.domain.OAuth2RefreshToken());
    final OAuth2AuthenticationKey authKey = new OAuth2AuthenticationKey(authentication);
    tokenEntity.setUserName(authKey.getUserName());
    tokenEntity.setClientId(authKey.getClientId());
    tokenEntity.setScopes(authKey.getScopes());
    tokenEntity.setAuthentication(SerializationUtils.serialize(authentication));
    tokenEntity.setValue(refreshToken.getValue());
    log.debug("Storing refresh token {}", tokenEntity);
    refreshTokenRepository.save(tokenEntity);
  }

  @Override
  public OAuth2RefreshToken readRefreshToken(@NotNull final String tokenValue) {

    log.debug("Reading refresh token by token value ...");
    return refreshTokenRepository.findByValue(tokenValue).orElse(null);
  }

  @Override
  public void removeRefreshToken(final OAuth2RefreshToken token) {

    log.debug("Removing refresh token ...");
    if (token != null) {
      removeRefreshToken(token.getValue());
    }
  }

  private void removeRefreshToken(final String tokenValue) {

    log.debug("Removing refresh token by value ...");
    if (tokenValue != null) {
      refreshTokenRepository.deleteByValue(tokenValue);
    }
  }

  @Override
  public OAuth2Authentication readAuthenticationForRefreshToken(
      final OAuth2RefreshToken token) {

    log.debug("Reading authentication by refresh token ...");
    if (token == null || token.getValue() == null) {
      return null;
    }
    return refreshTokenRepository
        .findByValue(token.getValue())
        .map(oAuth2RefreshToken -> (OAuth2Authentication) SerializationUtils.deserialize(
            oAuth2RefreshToken.getAuthentication()))
        .orElse(null);
  }

  @Override
  public void removeAccessTokenUsingRefreshToken(final OAuth2RefreshToken refreshToken) {

    log.debug("Removing refresh token by token value ...");
    if (refreshToken != null && refreshToken.getValue() != null) {
      accessTokenRepository.deleteByRefreshTokenValue(refreshToken.getValue());
    }
  }

  @Override
  public Collection<OAuth2AccessToken> findTokensByClientId(final String clientId) {

    log.debug("Finding access tokens by clientId [{}] ...", clientId);
    return CastUtils.cast(accessTokenRepository.findByClientId(clientId));
  }

  @Override
  public Collection<OAuth2AccessToken> findTokensByClientIdAndUserName(
      final String clientId, final String userName) {

    log.debug("Finding access tokens by clientId [{}] and user [{}] ...", clientId, userName);
    return CastUtils.cast(accessTokenRepository.findByClientIdAndUserName(clientId, userName));
  }

}

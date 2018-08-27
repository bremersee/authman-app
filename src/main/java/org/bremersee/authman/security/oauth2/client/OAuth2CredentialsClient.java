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

package org.bremersee.authman.security.oauth2.client;

import java.util.Collections;
import java.util.Map;
import javax.validation.constraints.NotNull;
import lombok.extern.slf4j.Slf4j;
import org.bremersee.authman.domain.OAuth2Client;
import org.bremersee.authman.domain.OAuth2ClientRepository;
import org.bremersee.authman.security.crypto.password.PasswordEncoder;
import org.bremersee.authman.security.crypto.password.PasswordEncoderImpl;
import org.bremersee.authman.security.crypto.password.PasswordEncoderProperties;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.client.support.BasicAuthorizationInterceptor;
import org.springframework.security.oauth2.common.exceptions.UnauthorizedClientException;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;

/**
 * @author Christian Bremer
 */
@Slf4j
public class OAuth2CredentialsClient implements OAuth2AccessTokenProvider {

  private final PasswordEncoder passwordEncoder;

  private OAuth2ClientRepository clientRepository;

  private RestTemplateBuilder restTemplateBuilder;

  private String tokenEndpoint;

  private String clientId;

  private String clientSecret;

  private String username;

  private String password;

  private String accessToken;

  private long expirationMillis;

  private OAuth2CredentialsClient() {
    final PasswordEncoderProperties pep = new PasswordEncoderProperties();
    pep.setAlgorithm("clear");
    pep.setStoreNoEncryptionFlag(true);
    this.passwordEncoder = new PasswordEncoderImpl(pep);
  }

  public OAuth2CredentialsClient(
      @NotNull final RestTemplateBuilder restTemplateBuilder,
      @NotNull final String tokenEndpoint,
      @NotNull final String clientId,
      @NotNull final String clientSecret) {

    this(restTemplateBuilder, tokenEndpoint, clientId, clientSecret, null, null);
  }

  public OAuth2CredentialsClient(
      @NotNull final RestTemplateBuilder restTemplateBuilder,
      @NotNull final String tokenEndpoint,
      @NotNull final String clientId,
      @NotNull final String clientSecret,
      final String username,
      final String password) {

    this();
    this.restTemplateBuilder = restTemplateBuilder;
    this.tokenEndpoint = tokenEndpoint;
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.username = username;
    this.password = password;
  }

  public OAuth2CredentialsClient(
      @NotNull final RestTemplateBuilder restTemplateBuilder,
      @NotNull final String tokenEndpoint,
      @NotNull final OAuth2ClientRepository clientRepository,
      @NotNull final String clientId) {

    this(restTemplateBuilder, tokenEndpoint, clientRepository, clientId, null, null);
  }

  public OAuth2CredentialsClient(
      @NotNull final RestTemplateBuilder restTemplateBuilder,
      @NotNull final String tokenEndpoint,
      @NotNull final OAuth2ClientRepository clientRepository,
      @NotNull final String clientId,
      final String username,
      final String password) {

    this();
    this.restTemplateBuilder = restTemplateBuilder;
    this.tokenEndpoint = tokenEndpoint;
    this.clientRepository = clientRepository;
    this.clientId = clientId;
    this.username = username;
    this.password = password;
  }

  private String getClientSecrets() {
    if (clientRepository != null && StringUtils.hasText(clientId)) {
      OAuth2Client client = clientRepository.findByClientId(clientId).orElse(null);
      if (client != null && !client.isClientSecretEncrypted()) {
        return passwordEncoder.getClearPassword(client.getClientSecret());
      }
    }
    return clientSecret;
  }

  private boolean isPasswordFlowAvailable() {
    return StringUtils.hasText(username) && StringUtils.hasText(password);
  }

  private String getGrantType() {
    return isPasswordFlowAvailable() ? "password" : "client_credentials";
  }

  private boolean isAccessTokenValid() {
    return StringUtils.hasText(accessToken) && expirationMillis > System.currentTimeMillis();
  }

  private void requestToken() {
    this.accessToken = null;
    final long start = System.currentTimeMillis();

    final RestTemplate restTemplate = restTemplateBuilder.build();
    restTemplate.getInterceptors().add(
        new BasicAuthorizationInterceptor(clientId, getClientSecrets()));

    final HttpHeaders httpHeaders = new HttpHeaders();
    httpHeaders.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
    httpHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

    final MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
    body.add("grant_type", getGrantType());
    if (isPasswordFlowAvailable()) {
      body.add("username", username);
      body.add("password", password);
    }

    final HttpEntity<MultiValueMap> httpEntity = new HttpEntity<>(body, httpHeaders);
    @SuppressWarnings("unchecked")
    Map<String, Object> tokenMap = restTemplate.exchange(
        tokenEndpoint, HttpMethod.POST, httpEntity, Map.class)
        .getBody();

    if (tokenMap != null) {
      this.accessToken = String.valueOf(tokenMap.get("access_token"));
      final int expiresIn = Integer.parseInt(String.valueOf(tokenMap.get("expires_in")));
      final long end = System.currentTimeMillis();
      this.expirationMillis =
          System.currentTimeMillis() + ((expiresIn - 1) * 1000L) - (end - start);
    }
  }

  @Override
  public String getAccessToken() {
    if (!isAccessTokenValid()) {
      requestToken();
      if (accessToken == null) {
        final UnauthorizedClientException e = new UnauthorizedClientException(
            "There is no access token for client [" + clientId + "].");
        log.error("Requesting an access token failed.", e);
      }
    }
    return accessToken;
  }

}

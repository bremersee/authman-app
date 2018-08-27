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

package org.bremersee.authman;

import java.security.KeyPair;
import lombok.extern.slf4j.Slf4j;
import org.bremersee.authman.domain.OAuth2AccessTokenRepository;
import org.bremersee.authman.domain.OAuth2ApprovalRepository;
import org.bremersee.authman.domain.OAuth2RefreshTokenRepository;
import org.bremersee.authman.mapper.OAuth2ApprovalMapper;
import org.bremersee.authman.security.crypto.password.PasswordEncoder;
import org.bremersee.authman.security.oauth2.provider.approval.OAuth2ApprovalStore;
import org.bremersee.authman.security.oauth2.provider.token.store.OAuth2TokenStore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import org.springframework.util.StringUtils;

/**
 * @author Christian Bremer
 */
@Configuration
@EnableAuthorizationServer
@EnableConfigurationProperties({AuthorizationServerProperties.class})
@Slf4j
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

  private AuthorizationServerProperties properties;

  private PasswordEncoder passwordEncoder;

  private OAuth2ApprovalRepository approvalRepository;

  private OAuth2ApprovalMapper approvalMapper;

  private OAuth2AccessTokenRepository accessTokenRepository;

  private OAuth2RefreshTokenRepository refreshTokenRepository;

  private ClientDetailsService clientDetailsService;

  private AuthenticationManager authenticationManager;

  @Autowired
  public AuthorizationServerConfiguration(
      AuthorizationServerProperties properties,
      PasswordEncoder passwordEncoder,
      OAuth2ApprovalRepository approvalRepository,
      OAuth2ApprovalMapper approvalMapper,
      OAuth2AccessTokenRepository accessTokenRepository,
      OAuth2RefreshTokenRepository refreshTokenRepository,
      @Qualifier("oauth2ClientDetailsService") ClientDetailsService clientDetailsService,
      @Qualifier("authenticationManagerBean") AuthenticationManager authenticationManager) {

    this.properties = properties;
    this.passwordEncoder = passwordEncoder;
    this.approvalRepository = approvalRepository;
    this.approvalMapper = approvalMapper;
    this.accessTokenRepository = accessTokenRepository;
    this.refreshTokenRepository = refreshTokenRepository;
    this.clientDetailsService = clientDetailsService;
    this.authenticationManager = authenticationManager;
  }

  @Bean
  public JwtAccessTokenConverter jwtAccessTokenConverter() {

    final JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
    if (org.springframework.util.StringUtils.hasText(properties.getJwtSigningKey())) {
      converter.setSigningKey(properties.getJwtSigningKey());
      if (StringUtils.hasText(properties.getJwtVerifierKey())) {
        converter.setVerifierKey(properties.getJwtVerifierKey());
      }
    } else {
      final DefaultResourceLoader resourceLoader = new DefaultResourceLoader();
      final KeyStoreKeyFactory keyStoreFactory = new KeyStoreKeyFactory(
          resourceLoader.getResource(properties.getJwtKeyStoreLocation()),
          properties.getJwtKeyStorePassword().toCharArray());
      final KeyPair keyPair;
      if (!StringUtils.hasText(properties.getJwtKeyPairPassword())) {
        keyPair = keyStoreFactory.getKeyPair(properties.getJwtKeyPairAlias());
      } else {
        keyPair = keyStoreFactory.getKeyPair(
            properties.getJwtKeyPairAlias(),
            properties.getJwtKeyPairPassword().toCharArray());
      }
      converter.setKeyPair(keyPair);
    }
    return converter;
  }

  @Bean
  public TokenStore tokenStore() {
    /*
    final JwtTokenStore tokenStore = new JwtTokenStore(jwtAccessTokenConverter());
    tokenStore.setApprovalStore(approvalStore());
    return tokenStore;
    */
    return new OAuth2TokenStore(accessTokenRepository, refreshTokenRepository);
  }

  @Bean
  public ApprovalStore approvalStore() {
    //return new InMemoryApprovalStore();

    final OAuth2ApprovalStore approvalStore = new OAuth2ApprovalStore(
        approvalRepository, approvalMapper);
    approvalStore.setHandleRevocationsAsExpiry(
        properties.isHandleApprovalRevocationsAsExpiry());
    return approvalStore;

  }

  @Override
  public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
    /*
    clients
        .inMemory()
        .withClient("bios")
        .secret("changeit")
        .authorities("ROLE_CLIENT")
        .scopes("bios")
        .autoApprove(true)
        .authorizedGrantTypes(
            "authorization_code", "client_credentials", "refresh_token", "password", "implicit");
    */
    clients.withClientDetails(clientDetailsService);
  }

  @Override
  public void configure(AuthorizationServerSecurityConfigurer security) {
    security
        .tokenKeyAccess(properties.getTokenKeyAccess())
        .checkTokenAccess(properties.getCheckTokenAccess())
        .realm(properties.getRealm())
        .passwordEncoder(passwordEncoder)
    ;
    if (properties.isAllowFormAuthenticationForClients()) {
      security.allowFormAuthenticationForClients();
    }
    if (properties.isSslOnly()) {
      security.sslOnly();
    }
  }

  @Override
  public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
    endpoints.authenticationManager(authenticationManager)
        .accessTokenConverter(jwtAccessTokenConverter());
    endpoints.tokenStore(tokenStore());
    endpoints.approvalStore(approvalStore());
  }
}

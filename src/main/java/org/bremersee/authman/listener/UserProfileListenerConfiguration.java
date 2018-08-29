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

package org.bremersee.authman.listener;

import feign.Client;
import feign.Request;
import feign.Retryer;
import feign.Retryer.Default;
import feign.Target;
import feign.codec.Decoder;
import feign.codec.Encoder;
import feign.codec.ErrorDecoder;
import feign.hystrix.HystrixFeign;
import org.bremersee.authman.domain.OAuth2ClientRepository;
import org.bremersee.authman.listener.UserProfileListenerProperties.UserProfileHttpListenerProperties;
import org.bremersee.authman.listener.api.UserProfileListenerApi;
import org.bremersee.authman.security.oauth2.client.OAuth2CredentialsClient;
import org.bremersee.authman.security.oauth2.client.OAuth2FeignRequestInterceptor;
import org.bremersee.common.exhandling.feign.FeignClientExceptionErrorDecoder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.cloud.openfeign.FeignClientsConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.util.StringUtils;

/**
 * @author Christian Bremer
 */
@Configuration
@EnableConfigurationProperties({UserProfileListenerProperties.class})
@Import(FeignClientsConfiguration.class)
public class UserProfileListenerConfiguration {

  private final UserProfileListenerFallback fallback = new UserProfileListenerFallback();

  private final UserProfileListenerProperties properties;

  private final Decoder decoder;

  private final Encoder encoder;

  private final Client client;

  private final ErrorDecoder errorDecoder;

  private final RestTemplateBuilder restTemplateBuilder;

  private final OAuth2ClientRepository clientRepository;

  @Autowired
  public UserProfileListenerConfiguration(
      final UserProfileListenerProperties properties,
      final Decoder decoder,
      final Encoder encoder,
      final Client client,
      final Jackson2ObjectMapperBuilder objectMapperBuilder,
      final RestTemplateBuilder restTemplateBuilder,
      final OAuth2ClientRepository clientRepository) {

    this.properties = properties;
    this.decoder = decoder;
    this.encoder = encoder;
    this.client = client;
    this.errorDecoder = new FeignClientExceptionErrorDecoder(objectMapperBuilder);
    this.restTemplateBuilder = restTemplateBuilder;
    this.clientRepository = clientRepository;
  }

  @Bean
  public UserProfileListener userProfileListener() {

    final UserProfileListenerImpl impl = new UserProfileListenerImpl();
    properties.getHttpListeners().forEach(props -> {
      if (props.isEnabled()) {
        impl.getHttpListeners().add(buildHttpListener(props));
      }
    });
    return impl;
  }

  private UserProfileListenerApi buildHttpListener(
      UserProfileHttpListenerProperties properties) {

    final OAuth2CredentialsClient tokenProvider = new OAuth2CredentialsClient(
        restTemplateBuilder,
        properties.getTokenEndpoint(),
        clientRepository,
        properties.getClientId(),
        properties.getUsername(),
        properties.getPassword()
    );

    final Retryer retryer = new Default(
        properties.getRetryPeriod(),
        properties.getRetryMaxPeriod(),
        properties.getRetryMaxAttempts());

    final Target<UserProfileListenerApi> target;
    if (StringUtils.hasText(properties.getFeignUrl())
        && StringUtils.hasText(properties.getFeignName())) {
      target = new Target.HardCodedTarget<>(UserProfileListenerApi.class,
          properties.getFeignName(), properties.getFeignUrl());
    } else if (StringUtils.hasText(properties.getFeignUrl())) {
      target = new Target.HardCodedTarget<>(UserProfileListenerApi.class,
          properties.getFeignUrl());
    } else if (StringUtils.hasText(properties.getFeignName())) {
      target = Target.EmptyTarget.create(UserProfileListenerApi.class,
          properties.getFeignName());
    } else {
      throw new IllegalArgumentException("Feign name and/or url must be present.");
    }

    // A feign builder without hystrix: Feign.builder()
    return HystrixFeign
        .builder()
        .client(client)
        .options(new Request.Options(
            properties.getConnectTimeoutMillis(),
            properties.getReadTimeoutMillis()))
        .decoder(decoder)
        .encoder(encoder)
        .errorDecoder(errorDecoder)
        .logLevel(properties.getFeignLogLevel())
        .requestInterceptor(new OAuth2FeignRequestInterceptor(tokenProvider))
        .retryer(retryer)
        .target(target, fallback);
  }
}

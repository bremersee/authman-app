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

import feign.RequestInterceptor;
import feign.RequestTemplate;
import javax.validation.constraints.NotNull;

/**
 * @author Christian Bremer
 */
public class OAuth2FeignRequestInterceptor implements RequestInterceptor {

  private static final String BEARER = "Bearer";

  private static final String AUTHORIZATION = "Authorization";

  private final OAuth2AccessTokenProvider tokenProvider;

  org.springframework.cloud.security.oauth2.client.feign.OAuth2FeignRequestInterceptor a;

  public OAuth2FeignRequestInterceptor(
      @NotNull final OAuth2AccessTokenProvider tokenProvider) {
    this.tokenProvider = tokenProvider;
  }

  @Override
  public void apply(RequestTemplate requestTemplate) {
    requestTemplate.header(AUTHORIZATION, BEARER + " " + tokenProvider.getAccessToken());
  }
}

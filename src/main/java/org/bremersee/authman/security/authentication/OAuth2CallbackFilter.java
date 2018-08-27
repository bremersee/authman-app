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

package org.bremersee.authman.security.authentication;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.constraints.NotNull;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.ArrayUtils;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.authentication.session.CompositeSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;

/**
 * @author Christian Bremer
 */
@Slf4j
public class OAuth2CallbackFilter extends AbstractAuthenticationProcessingFilter {

  private final OAuth2AuthenticationProperties properties;

  private final OAuth2StateCache stateCache;

  private final ForeignUserProfileRequestor foreignUserProfileRequestor;

  @Setter
  private RestTemplateBuilder restTemplateBuilder = new RestTemplateBuilder();

  public OAuth2CallbackFilter(
      @NotNull final OAuth2AuthenticationProperties properties,
      @NotNull final ForeignUserProfileRequestor foreignUserProfileRequestor,
      @NotNull final RequestMatcher requiresAuthenticationRequestMatcher) {

    super(requiresAuthenticationRequestMatcher);

    this.properties = properties;
    this.foreignUserProfileRequestor = foreignUserProfileRequestor;
    this.stateCache = new OAuth2StateCache(properties.getStateKeyName());

    setAuthenticationSuccessHandler(new OAuth2AuthenticationSuccessHandler());

    final List<SessionAuthenticationStrategy> delegateStrategies = new ArrayList<>();
    delegateStrategies.add(new ChangeSessionIdAuthenticationStrategy());
    setSessionAuthenticationStrategy(
        new CompositeSessionAuthenticationStrategy(delegateStrategies));

    setAuthenticationFailureHandler(new OAuth2AuthenticationFailureHandler());
  }

  @Override
  public Authentication attemptAuthentication(
      final HttpServletRequest request,
      final HttpServletResponse response) {

    log.debug("Attempting OAuth2 authentication ...");

    final Map<String, String[]> params = request.getParameterMap();
    if (log.isDebugEnabled()) {
      params.forEach((s, strings) -> log.info(
          "Parameter from OAuth2: {}={}", s, ArrayUtils.toString(strings, "null")));
    }

    final String error = request.getParameter(properties.getResponseErrorParameter());
    if (StringUtils.hasText(error)) {
      final OAuth2AuthenticationException exception = new OAuth2AuthenticationException(error);
      log.error("OAuth2 login returns an error.", exception);
      throw exception;
    }

    final String savedState = stateCache.getState(request);
    OAuth2AuthenticationException.validateNotBlank(savedState,
        "Saved state is not present.");
    final String state = request.getParameter(properties.getResponseStateParameter());
    stateCache.removeState(request);
    OAuth2AuthenticationException.validateNotBlank(state, "State is not present.");
    if (!savedState.equals(state)) {
      final OAuth2AuthenticationException exception = new OAuth2AuthenticationException(
          "Saved state and state from OAuth2 Provider are not equal.");
      log.error("Facebook login failed.", exception); // NOSONAR
      throw exception;
    }

    final String code = request.getParameter(properties.getResponseCodeParameter());
    if (!StringUtils.hasText(code)) {
      OAuth2AuthenticationException exception = new OAuth2AuthenticationException(
          "Got no valid response from OAuth2 Provider.");
      log.error("OAuth2 login failed.", exception);
      throw exception;
    }

    final CodeExchangeResponse credentials = exchangeCode(code);
    final ForeignUserProfile profile = foreignUserProfileRequestor
        .getForeignUserProfile(credentials);

    final Authentication authRequest = new OAuth2AuthenticationToken(properties.getProvider(),
        credentials,
        profile, properties.scopes());

    return getAuthenticationManager().authenticate(authRequest);
  }

  @SuppressWarnings("WeakerAccess")
  protected CodeExchangeResponse exchangeCode(@NotNull final String code) {

    final RestTemplate restTemplate = restTemplateBuilder.build();
    final Map<String, Object> params = properties.buildExchangeCodeRequestParameters(
        code, null, null);
    final String url = properties.getTokenUrlTemplate();
    final HttpMethod httpMethod = properties.getTokenMethod();
    HttpEntity<String> httpEntity = new HttpEntity<>("");
    for (Map.Entry<String, String> headerEntry : properties.getTokenHeaders().entrySet()) {
      httpEntity.getHeaders().set(headerEntry.getKey(), headerEntry.getValue());
    }
    final ResponseEntity<CodeExchangeResponse> response = restTemplate
        .exchange(url, httpMethod, httpEntity,
            CodeExchangeResponse.class, params);
    return response.getBody();
  }

}

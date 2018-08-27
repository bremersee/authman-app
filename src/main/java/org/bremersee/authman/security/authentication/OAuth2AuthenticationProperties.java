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

import java.io.IOException;
import java.io.Serializable;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import javax.validation.constraints.NotNull;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.util.StringUtils;

/**
 * @author Christian Bremer
 */
@Getter
@Setter
@ToString(exclude = {"clientSecret"})
@EqualsAndHashCode(exclude = {"clientSecret"})
@NoArgsConstructor
@Slf4j
public abstract class OAuth2AuthenticationProperties implements Serializable {

  private static final long serialVersionUID = 5704725929075936143L;

  private String provider;


  private String stateKeyName = getProvider() + ".state";

  private String loginUrlTemplate;

  private String clientId;

  private String clientSecret;

  private String redirectUri;

  private String redirectUriProfileConnect;

  // must be 'code', because 'token' would result in hash fragments, which can't be parsed by HttpServletRequest
  private String responseType = "code";

  private String scope;

  private String scopeSeparator = " ";

  private Map<String, String> additionalLoginParameters = new LinkedHashMap<>();


  private String responseCodeParameter = "code";

  private String responseStateParameter = "state";

  private String responseErrorParameter = "error";


  private String tokenUrlTemplate;

  private HttpMethod tokenMethod = HttpMethod.GET;

  private Map<String, String> additionalTokenParameters = new LinkedHashMap<>();

  private Map<String, String> tokenHeaders = new LinkedHashMap<>();


  private String apiBaseUrl;

  private String profilePathTemplate;


  public Set<String> scopes() {
    LinkedHashSet<String> scopes = new LinkedHashSet<>();
    if (StringUtils.hasText(getScope())) {
      final String sep;
      if (scopeSeparator == null || scopeSeparator.length() == 0) {
        sep = " ";
      } else {
        sep = scopeSeparator;
      }
      String[] scopeArray = getScope().split(Pattern.quote(sep));
      for (String entry : scopeArray) {
        String trimmedEntry = entry.trim();
        if (StringUtils.hasText(trimmedEntry)) {
          scopes.add(trimmedEntry);
        }
      }
    }
    return scopes;
  }

  @SuppressWarnings("WeakerAccess")
  public String buildLoginUrl(
      final String redirectUri,
      final String responseType,
      final String scope,
      final String state,
      final Map<String, String> additionalParameters) throws IOException {

    final String redirectUri_ = StringUtils.hasText(redirectUri) ? redirectUri : this.redirectUri;
    final String responseType_ = StringUtils.hasText(responseType)
        ? responseType : this.responseType;
    final String scope_ = StringUtils.hasText(scope) ? scope : this.scope;

    String url = this.getLoginUrlTemplate();
    url = url.replace("{clientId}",
        URLEncoder.encode(this.getClientId(), StandardCharsets.UTF_8.name()));
    url = url.replace("{redirectUri}",
        URLEncoder.encode(redirectUri_, StandardCharsets.UTF_8.name()));
    url = url.replace("{responseType}",
        URLEncoder.encode(responseType_, StandardCharsets.UTF_8.name()));
    url = url.replace("{scope}",
        URLEncoder.encode(scope_, StandardCharsets.UTF_8.name()));
    url = url.replace("{state}", URLEncoder.encode(state, StandardCharsets.UTF_8.name()));
    final String loginUrl = addAdditionalParameters(url, additionalParameters);
    log.info("msg=[OAuth2 redirect] loginUrl=[{}]", loginUrl);
    return loginUrl;
  }

  @SuppressWarnings("WeakerAccess")
  private String addAdditionalParameters(
      final String url,
      final Map<String, String> additionalParameters) throws IOException {

    final Map<String, String> params = new LinkedHashMap<>(getAdditionalLoginParameters());
    if (additionalParameters != null) {
      params.putAll(additionalParameters);
    }
    log.info("msg=[OAuth2 redirect] additionalParameters=[{}]", params);
    final boolean urlHasParameter = url.contains("?");
    final StringBuilder urlBuilder = new StringBuilder(url);
    for (Map.Entry<String, String> param : params.entrySet()) {
      final String value = StringUtils.hasText(param.getValue()) ? URLEncoder
          .encode(param.getValue(), StandardCharsets.UTF_8.name()) : "";
      if (urlHasParameter) {
        urlBuilder.append('&');
      } else {
        urlBuilder.append('?');
      }
      urlBuilder.append(URLEncoder.encode(param.getKey(), StandardCharsets.UTF_8.name()));
      urlBuilder.append("=").append(value);
    }
    return urlBuilder.toString();
  }

  public Map<String, Object> buildExchangeCodeRequestParameters(
      @NotNull final String code,
      final String redirectUri,
      final Map<String, String> additionalTokenParameters) {

    final String redirectUri_ = StringUtils.hasText(redirectUri) ? redirectUri : this.redirectUri;
    final Map<String, String> tokenParams = new LinkedHashMap<>(getAdditionalTokenParameters());
    if (additionalTokenParameters != null) {
      tokenParams.putAll(additionalTokenParameters);
    }

    final Map<String, Object> params = new LinkedHashMap<>();
    params.put("clientId", getClientId());
    params.put("clientSecret", getClientSecret());
    params.put("code", code);
    params.put("redirectUri", redirectUri_);
    if (!tokenParams.isEmpty()) {
      params.putAll(tokenParams);
    }
    return params;
  }

}

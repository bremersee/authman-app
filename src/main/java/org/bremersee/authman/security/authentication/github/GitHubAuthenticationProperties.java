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

package org.bremersee.authman.security.authentication.github;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.bremersee.authman.security.authentication.OAuth2AuthenticationProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.http.HttpMethod;

/**
 * @author Christian Bremer
 */
@ConfigurationProperties("bremersee.oauth2.github")
@Getter
@Setter
@ToString(callSuper = true)
@EqualsAndHashCode(callSuper = true)
public class GitHubAuthenticationProperties extends OAuth2AuthenticationProperties {

  //Accept: application/vnd.github.v3+json

  // ISO 8601: YYYY-MM-DDTHH:MM:SSZ

  // Authorization: token {accessToken} wird auch unterstützt

  public GitHubAuthenticationProperties() {
    super.setProvider("github");

    super.setLoginUrlTemplate("https://github.com/login/oauth/authorize"
        + "?client_id={clientId}"
        + "&redirect_uri={redirectUri}"
        + "&scope={scope}"
        + "&state={state}");
    super.setResponseType("code");
    super.setScope("user:email");
    super.setTokenUrlTemplate("https://github.com/login/oauth/access_token"
        + "?client_id={clientId}"
        + "&client_secret={clientSecret}"
        + "&redirect_uri={redirectUri}"
        + "&code={code}");
    super.setTokenMethod(HttpMethod.POST);
    super.setApiBaseUrl("https://api.github.com");
    super.setProfilePathTemplate("/user?access_token={accessToken}");
  }
}

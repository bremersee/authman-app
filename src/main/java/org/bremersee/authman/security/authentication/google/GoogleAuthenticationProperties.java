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

package org.bremersee.authman.security.authentication.google;

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
@ConfigurationProperties("bremersee.oauth2.google")
@Getter
@Setter
@ToString(callSuper = true)
@EqualsAndHashCode(callSuper = true)
public class GoogleAuthenticationProperties extends OAuth2AuthenticationProperties {

  // Authorization: Bearer {accessToken} is also supported

  public GoogleAuthenticationProperties() {
    super.setProvider("google");
    super.setScopeSeparator(" ");

    super.setLoginUrlTemplate("https://accounts.google.com/o/oauth2/v2/auth"
        + "?client_id={clientId}"
        + "&redirect_uri={redirectUri}"
        + "&response_type={responseType}"
        + "&scope={scope}"
        + "&state={state}"
        + "&access_type={accessType}"
        + "&include_granted_scopes={includeGrantedScopes}");
    super.getAdditionalLoginParameters().put("includeGrantedScopes", "false");
    super.getAdditionalLoginParameters().put("accessType", "online");

    super.setResponseType("code");
    super.setScope("profile email");
    super.setTokenUrlTemplate("https://www.googleapis.com/oauth2/v4/token"
        + "?client_id={clientId}"
        + "&client_secret={clientSecret}"
        + "&redirect_uri={redirectUri}"
        + "&code={code}"
        + "&grant_type=authorization_code");
    super.setTokenMethod(HttpMethod.POST);
    super.setApiBaseUrl("https://www.googleapis.com");
    super.setProfilePathTemplate("/plus/v1/people/me?access_token={accessToken}");
  }
}

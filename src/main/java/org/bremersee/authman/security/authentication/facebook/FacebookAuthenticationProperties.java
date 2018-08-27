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

package org.bremersee.authman.security.authentication.facebook;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.bremersee.authman.security.authentication.OAuth2AuthenticationProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * @author Christian Bremer
 */
@ConfigurationProperties("bremersee.oauth2.facebook")
@Getter
@Setter
@ToString(callSuper = true)
@EqualsAndHashCode(callSuper = true)
public class FacebookAuthenticationProperties extends OAuth2AuthenticationProperties {

  // https://developers.facebook.com/docs/graph-api/reference/user/picture/
  private String picturePathTemplate = "/{userId}/picture?access_token={accessToken}"; // NOSONAR

  public FacebookAuthenticationProperties() {
    super.setProvider("facebook");
    super.setScopeSeparator(",");

    super.setLoginUrlTemplate("https://www.facebook.com/v2.8/dialog/oauth"
        + "?client_id={clientId}"
        + "&redirect_uri={redirectUri}"
        + "&response_type={responseType}"
        + "&scope={scope}&state={state}");
    super.setResponseType("code");
    super.setScope("public_profile,email");
    super.setTokenUrlTemplate("https://graph.facebook.com/v2.8/oauth/access_token"
        + "?client_id={clientId}"
        + "&redirect_uri={redirectUri}"
        + "&client_secret={clientSecret}"
        + "&code={code}");
    super.setApiBaseUrl("https://graph.facebook.com/v2.8");
    super.setProfilePathTemplate("/me"
        + "?access_token={accessToken}"
        + "&fields=id,name,gender,first_name,middle_name,last_name,name_format,email,locale,"
        + "timezone,verified,website");
  }

}

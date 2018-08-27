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

package org.bremersee.authman.domain;

import java.util.Date;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.springframework.data.annotation.Transient;
import org.springframework.data.mongodb.core.index.CompoundIndex;
import org.springframework.data.mongodb.core.index.CompoundIndexes;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.util.StringUtils;

/**
 * @author Christian Bremer
 */
@Getter
@Setter
@ToString(callSuper = true)
@EqualsAndHashCode(callSuper = true)
@NoArgsConstructor
@Document(collection = "oauthAccessToken")
@CompoundIndexes({
    @CompoundIndex(
        name = "userNameAndClientId",
        def = "{ 'userName': 1, 'clientId': 1 }",
        sparse = true
    ),
    @CompoundIndex(
        name = "userNameAndClientIdAndScopes",
        def = "{ 'userName': 1, 'clientId': 1, 'scopes': 1 }",
        sparse = true)
})
public class OAuth2AccessToken extends AbstractAuditBase // NOSONAR
    implements org.springframework.security.oauth2.common.OAuth2AccessToken {

  private static final long serialVersionUID = -6620739953574774048L;

  @Field("userName")
  private String userName; // extracted from the authentication

  @Indexed
  @Field("clientId")
  private String clientId; // extracted from the authentication

  @Field("scopes")
  private String scopes; // extracted from the authentication

  @Field("authentication")
  private byte[] authentication;

  @Indexed(unique = true)
  @Field("value")
  private String value;

  @Field("expiration")
  private Date expiration;

  @Field("tokenType")
  private String tokenType = BEARER_TYPE.toLowerCase();

  @Indexed(sparse = true)
  @Field("refreshTokenValue")
  private String refreshTokenValue;

  @Field("scope")
  private Set<String> scope = new LinkedHashSet<>(); // NOSONAR

  @Field("additionalInformation")
  private Map<String, Object> additionalInformation = new LinkedHashMap<>(); // NOSONAR

  @Transient
  @Override
  public OAuth2RefreshToken getRefreshToken() {
    if (!StringUtils.hasText(this.refreshTokenValue)) {
      return null;
    }
    return new DefaultOAuth2RefreshToken(this.refreshTokenValue);
  }

  @Transient
  @Override
  public boolean isExpired() {
    return expiration != null && expiration.before(new Date());
  }

  @Transient
  @Override
  public int getExpiresIn() {
    if (expiration == null) {
      return 0;
    }
    return (int) ((expiration.getTime() - System.currentTimeMillis()) / 1000L);
  }

}

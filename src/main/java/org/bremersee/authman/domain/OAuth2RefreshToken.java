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

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

/**
 * @author Christian Bremer
 */
@Getter
@Setter
@ToString
@EqualsAndHashCode(callSuper = true)
@NoArgsConstructor
@Document(collection = "oauthRefreshToken")
public class OAuth2RefreshToken extends AbstractAuditBase // NOSONAR
    implements org.springframework.security.oauth2.common.OAuth2RefreshToken {

  private static final long serialVersionUID = 1745666728232428401L;

  @Field("userName")
  private String userName; // extracted from the authentication

  @Field("clientId")
  private String clientId; // extracted from the authentication

  @Field("scopes")
  private String scopes; // extracted from the authentication

  @Field("authentication")
  private byte[] authentication;

  @Indexed(unique = true)
  @Field("value")
  private String value;

}

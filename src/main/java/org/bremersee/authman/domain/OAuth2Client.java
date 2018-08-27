/*
 * Copyright 2015 the original author or authors.
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

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
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
@ToString(callSuper = true, exclude = {"clientSecret"})
@EqualsAndHashCode(callSuper = true)
@NoArgsConstructor
@Document(collection = "oauth2Client")
public class OAuth2Client extends AbstractAuditBase {

  private static final long serialVersionUID = 1L;

  @Field("displayName")
  private String displayName;

  @Indexed(unique = true)
  @Field("clientId")
  private String clientId;

  @Field("clientSecret")
  private String clientSecret;

  @Field("clientSecretEncrypted")
  private boolean clientSecretEncrypted;

  @Field("resourceIds")
  private Set<String> resourceIds = new LinkedHashSet<>();

  @Indexed(sparse = true)
  @Field("scope")
  private Set<String> scope = new LinkedHashSet<>();

  @Field("authorizedGrantTypes")
  private Set<String> authorizedGrantTypes = new LinkedHashSet<>();

  @Field("registeredRedirectUri")
  private Set<String> registeredRedirectUri = new LinkedHashSet<>();

  @Field("accessTokenValiditySeconds")
  private Integer accessTokenValiditySeconds;

  @Field("refreshTokenValiditySeconds")
  private Integer refreshTokenValiditySeconds;

  @Field("autoApproveScopes")
  private Set<String> autoApproveScopes = new LinkedHashSet<>();

  @Field("additionalInformation")
  private Map<String, Object> additionalInformation = new LinkedHashMap<>(); // NOSONAR

}

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
import java.util.LinkedHashSet;
import java.util.Set;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.springframework.data.mongodb.core.index.CompoundIndex;
import org.springframework.data.mongodb.core.index.CompoundIndexes;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

/**
 * @author Christian Bremer
 */
@Getter
@Setter
@ToString(callSuper = true, exclude = {"scopes", "accessToken", "refreshToken"})
@EqualsAndHashCode(callSuper = true)
@NoArgsConstructor
@Document(collection = "oauth2ForeignToken")
@CompoundIndexes({
    @CompoundIndex(name = "oauth2_token_uk_provider_foreign_user",
        def = "{'provider': 1, 'foreignUserName': 1 }",
        unique = true),
    @CompoundIndex(name = "oauth2_token_uk_provider_user",
        def = "{'provider': 1, 'userName': 1 }",
        unique = true)
})
public class OAuth2ForeignToken extends AbstractAuditBase {

  @Indexed
  @Field("userName")
  private String userName;

  @Indexed
  @Field("provider")
  private String provider;

  @Field("foreignUserName")
  private String foreignUserName;

  @Field("scope")
  private Set<String> scopes = new LinkedHashSet<>();

  @Field("accessToken")
  private String accessToken;

  @Field("tokenType")
  private String tokenType;

  @Field("expiresAt")
  private Date expiresAt;

  @Field("refreshToken")
  private String refreshToken;

  @Field("idToken")
  private String idToken;

}

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

package org.bremersee.authman.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

/**
 * @author Christian Bremer
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(Include.NON_NULL)
@JsonPropertyOrder(alphabetic = true)
@Getter
@Setter
@ToString(callSuper = true, exclude = {"clientSecret"})
@EqualsAndHashCode(callSuper = false, of = {"clientId"})
@NoArgsConstructor
@ApiModel(
    value = "OAuth2Client",
    description = "The oauth2 client."
)
public class OAuth2ClientDto extends AbstractAuditDto implements Comparable<OAuth2ClientDto> {

  private static final long serialVersionUID = -2588891000879084480L;

  @JsonProperty(value = "clientId", required = true)
  @ApiModelProperty(value = "The name of the client.", required = true)
  private String clientId;

  @JsonProperty(value = "clientSecret")
  @ApiModelProperty(value = "The client secret.")
  private String clientSecret;

  @JsonProperty(value = "clientSecretEncrypted")
  @ApiModelProperty(value = "Is the client secret encrypted?")
  private Boolean clientSecretEncrypted;

  @JsonProperty(value = "displayName")
  @ApiModelProperty(value = "The display name of the client.")
  private String displayName;

  @JsonProperty(value = "resourceIds")
  @ApiModelProperty(value = "The oauth2 resource IDs.")
  private Set<String> resourceIds = new LinkedHashSet<>();

  @JsonProperty(value = "scope")
  @ApiModelProperty(value = "The oauth2 scopes.")
  private Set<String> scope = new LinkedHashSet<>();

  @JsonProperty(value = "authorizedGrantTypes")
  @ApiModelProperty(value = "The oauth2 authorized grant types.")
  private Set<String> authorizedGrantTypes = new LinkedHashSet<>();

  @JsonProperty(value = "registeredRedirectUri")
  @ApiModelProperty(value = "The registered redirect URIs.")
  private Set<String> registeredRedirectUri = new LinkedHashSet<>();

  /*
  @JsonProperty(value = "roles")
  @ApiModelProperty(value = "The granted authorities of the client.")
  private Set<String> roles = new LinkedHashSet<>();
  */

  @JsonProperty(value = "accessTokenValiditySeconds")
  @ApiModelProperty(value = "The duration of the validity of the access token.")
  private Integer accessTokenValiditySeconds;

  @JsonProperty(value = "refreshTokenValiditySeconds")
  @ApiModelProperty(value = "The duration of the validity of the refresh token.")
  private Integer refreshTokenValiditySeconds;

  @JsonProperty(value = "autoApproveScopes")
  @ApiModelProperty(value = "The scopes that are auto approved ('true' for all).")
  private Set<String> autoApproveScopes = new LinkedHashSet<>();

  @ApiModelProperty("Additional information")
  private Map<String, Object> additionalInformation = new LinkedHashMap<>(); // NOSONAR

  @Override
  public int compareTo(final OAuth2ClientDto other) {
    final String s0 = getClientId() == null ? "" : getClientId();
    final String s1 = other.getClientId() == null ? "" : other.getClientId();
    return s0.compareTo(s1);
  }

}

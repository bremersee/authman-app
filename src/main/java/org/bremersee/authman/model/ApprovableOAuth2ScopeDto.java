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

package org.bremersee.authman.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import java.io.Serializable;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * @author Christian Bremer
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder(alphabetic = true)
@Data
@NoArgsConstructor
@AllArgsConstructor
@ApiModel(value = "ApprovableOAuth2Scope", description = "A scope that can be approved by an user.")
public class ApprovableOAuth2ScopeDto implements Serializable,
    Comparable<ApprovableOAuth2ScopeDto> {

  private static final long serialVersionUID = 963279609651389484L;

  @JsonProperty(value = "scope", required = true)
  @ApiModelProperty(value = "The oauth2 scope.", required = true)
  private String scope;

  @JsonProperty(value = "description")
  @ApiModelProperty(value = "The description of the oauth2 scope.")
  private String description;

  @JsonProperty(value = "approved", defaultValue = "false")
  @ApiModelProperty(value = "Is the scope approved?")
  private boolean approved;

  @Override
  public int compareTo(final ApprovableOAuth2ScopeDto other) {
    final String s0 = scope == null ? "" : scope;
    final String s1 = other.getScope() == null ? "" : other.getScope();
    return s0.compareTo(s1);
  }
}

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

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import java.util.Map;
import java.util.TreeMap;
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
@JsonAutoDetect(
    fieldVisibility = Visibility.ANY,
    getterVisibility = Visibility.NONE,
    creatorVisibility = Visibility.NONE,
    isGetterVisibility = Visibility.NONE,
    setterVisibility = Visibility.NONE
)
@Getter
@Setter
@ToString(callSuper = true)
@EqualsAndHashCode(callSuper = false, of = {"scope"})
@NoArgsConstructor
@ApiModel(
    value = "OAuth2Scope",
    description = "An OAuth2 Scope with descriptions in different languages.")
public class OAuth2ScopeDto extends AbstractAuditDto implements Comparable<OAuth2ScopeDto> {

  @JsonProperty(value = "scope", required = true)
  @ApiModelProperty(value = "The oauth2 scope.", required = true)
  private String scope;

  @JsonProperty(value = "visibility", defaultValue = "PUBLIC")
  @ApiModelProperty(value = "The visibility of the scope.")
  private OAuth2ScopeVisibility visibility = OAuth2ScopeVisibility.PUBLIC;

  @JsonProperty(value = "description")
  @ApiModelProperty(value = "The description of the scope.")
  private String description;

  @JsonProperty(value = "defaultLanguage")
  @ApiModelProperty(value = "The default language.")
  private String defaultLanguage;

  @JsonProperty(value = "descriptions")
  @ApiModelProperty("Descriptions of the scope in different languages.")
  private Map<String, String> descriptions = new TreeMap<>();

  @Override
  public int compareTo(final OAuth2ScopeDto other) {
    final String s0 = scope == null ? "" : scope;
    final String s1 = other.getScope() == null ? "" : other.getScope();
    return s0.compareTo(s1);
  }

}
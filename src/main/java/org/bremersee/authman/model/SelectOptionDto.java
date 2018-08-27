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
import java.io.Serializable;
import lombok.AllArgsConstructor;
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
@ToString
@EqualsAndHashCode
@NoArgsConstructor
@AllArgsConstructor
@ApiModel(
    value = "SelectOption",
    description = "An option of a html select input element.")
public class SelectOptionDto implements Serializable, Comparable<SelectOptionDto> {

  private static final long serialVersionUID = -1811407290501112995L;

  @ApiModelProperty(value = "The value of the select option.", required = true)
  @JsonProperty(value = "value", required = true)
  private String value;

  @ApiModelProperty(value = "The displayed value of the select option.")
  @JsonProperty(value = "displayValue")
  private String displayValue;

  @ApiModelProperty(value = "Is the option selected?")
  @JsonProperty(value = "selected", defaultValue = "false")
  private boolean selected;

  @Override
  public int compareTo(SelectOptionDto selectOptionDto) {
    String s0 = this.displayValue == null ? "" : this.displayValue;
    String s1 = selectOptionDto != null && selectOptionDto.displayValue != null
        ? selectOptionDto.displayValue : "";
    int c = s0.compareToIgnoreCase(s1);
    if (c != 0) {
      return c;
    } else {
      s0 = this.value == null ? "" : this.value;
      s1 = selectOptionDto != null && selectOptionDto.value != null ? selectOptionDto.value : "";
      return s0.compareTo(s1);
    }
  }

}

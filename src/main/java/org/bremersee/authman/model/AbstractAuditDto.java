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
import io.swagger.annotations.ApiModelProperty;
import java.io.Serializable;
import java.util.Date;
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
public class AbstractAuditDto implements Serializable {

  private static final long serialVersionUID = -3229201285733497168L;

  @JsonProperty("id")
  @ApiModelProperty(value = "The ID of the entity.")
  private String id;

  @JsonProperty("_version")
  @ApiModelProperty(value = "The version of the entity.")
  private Long version;

  @JsonProperty("_created")
  @ApiModelProperty(value = "The creation date of the entity.")
  private Date created;

  @JsonProperty("_created_by")
  @ApiModelProperty(value = "The name of the user who created the entity.")
  private String createdBy;

  @JsonProperty("_modified")
  @ApiModelProperty(value = "The modification date of the entity.")
  private Date modified;

  @JsonProperty("_modified_by")
  @ApiModelProperty(value = "The name of the user who made the last modification.")
  private String modifiedBy;

}

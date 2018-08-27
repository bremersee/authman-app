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
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import java.io.Serializable;
import java.util.Locale;
import java.util.TimeZone;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

/**
 * @author Christian Bremer
 */
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonPropertyOrder(alphabetic = true)
@Getter
@Setter
@ToString(callSuper = true, exclude = {"password"})
@NoArgsConstructor
@ApiModel(
    value = "UserProfileCreateRequest",
    description = "The create request of an user."
)
public class UserProfileCreateRequestDto implements Serializable {

  private static final long serialVersionUID = -434418974334969783L;

  @JsonProperty(value = "userName", required = true)
  @ApiModelProperty(value = "The login name of the user.", required = true)
  private String userName;

  @JsonProperty(value = "password", required = true)
  @ApiModelProperty(value = "The clear password of the user.", required = true)
  private String password;

  @JsonProperty(value = "displayName")
  @ApiModelProperty(value = "The first and last name of the user.")
  private String displayName;

  @JsonProperty(value = "preferredLocale")
  @ApiModelProperty(value = "The preferred locale of the user.")
  private String preferredLocale = Locale.getDefault().toString();

  @JsonProperty(value = "preferredTimeZoneId")
  @ApiModelProperty(value = "The preferred time zone of the user.")
  private String preferredTimeZoneId = TimeZone.getDefault().getID();

  @JsonProperty(value = "email", required = true)
  @ApiModelProperty(value = "The email address of the user.", required = true)
  private String email;

  @JsonProperty(value = "sambaSettings")
  @ApiModelProperty(value = "The samba settings of the user.")
  private SambaSettingsDto sambaSettings;

}

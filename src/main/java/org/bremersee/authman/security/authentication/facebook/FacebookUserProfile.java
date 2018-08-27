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

package org.bremersee.authman.security.authentication.facebook;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.math.BigInteger;
import java.util.Locale;
import java.util.TimeZone;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.apache.commons.lang3.LocaleUtils;
import org.bremersee.authman.security.authentication.ForeignUserProfile;
import org.springframework.util.StringUtils;

/**
 * @author Christian Bremer
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@Getter
@Setter
@ToString
@EqualsAndHashCode
@NoArgsConstructor
public class FacebookUserProfile implements ForeignUserProfile {

  private static final long serialVersionUID = 8850716660328023798L;

  @JsonProperty(value = "id", required = true)
  private String id;

  @JsonProperty(value = "name")
  private String displayName;

  @JsonProperty(value = "gender")
  private String gender;

  @JsonProperty(value = "first_name")
  private String firstName;

  @JsonProperty(value = "middle_name")
  private String middleName;

  @JsonProperty(value = "last_name", required = true)
  private String lastName;

  @JsonProperty(value = "name_format")
  private String nameFormat;

  @JsonProperty(value = "email", required = true)
  private String email;

  @JsonProperty(value = "locale")
  private String localeStr;

  @JsonProperty(value = "timezone")
  private BigInteger timezoneOffset;

  @JsonProperty(value = "verified")
  private Boolean verified;

  @JsonProperty(value = "website")
  private String website;

  @JsonIgnore
  @Override
  public String getName() {
    return id;
  }

  @JsonIgnore
  @Override
  public Locale getLocale() {
    if (!StringUtils.hasText(localeStr)) {
      return null;
    }
    return LocaleUtils.toLocale(localeStr.replace("-", "_"));
  }

  @JsonIgnore
  @Override
  public TimeZone getTimeZone() {
    // TODO timezoneOffset
    return null;
  }

}

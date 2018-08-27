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

package org.bremersee.authman.validation;

import java.util.regex.Pattern;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * @author Christian Bremer
 */
@ConfigurationProperties("bremersee.validation")
@Component
@Getter
@Setter
@ToString
@EqualsAndHashCode
public class ValidationProperties {

  private int userNameMinLength = 3;

  private int userNameMaxLength = 75;

  /**
   * This user name regex can be used in browsers.
   */
  private String userNameRegex = "^[a-zA-Z0-9._-]{3,75}$";

  private Integer userNameRegexFlags;

  /**
   * The exact regex is not accepted by some browsers.
   * <pre>
   * ^(?=.{8,20}$)(?![_.])(?!.*[_.]{2})[a-zA-Z0-9._]+(?<![_.])$
   *  └─────┬────┘└───┬──┘└─────┬─────┘└─────┬─────┘ └───┬───┘
   *        │         │         │            │           no _ or . at the end
   *        │         │         │            │
   *        │         │         │            allowed characters
   *        │         │         │
   *        │         │         no __ or _. or ._ or .. inside
   *        │         │
   *        │         no _ or . at the beginning
   *        │
   *        username is 8-20 characters long
   * </pre>
   */
  private String userNameExactRegex = "^(?=.{3,75}$)(?![-_.])(?!.*[_.]{2})[a-zA-Z0-9._-]+(?<![-_.])$";

  private Integer userNameExactRegexFlags;

  /**
   * Password expression that requires one lower case letter, one upper case letter, one digit, 8-75
   * length, and no spaces.
   */
  private String passwordRegex = "^(?=.*\\d)(?=.*[a-z])(?=.*[A-Z])(?!.*\\s).{8,75}$"; // NOSONAR

  private Integer passwordRegexFlags;

  private String emailRegex = "^\\S+@\\S+$";

  private Integer emailRegexFlags;

  private String mobileRegex = "^0049\\d{5,15}$";

  private Integer mobileRegexFlags;

  private String clientIdRegex = "^[a-zA-Z0-9._-]{14,75}$";

  private Integer clientIdRegexFlags;

  private String clientSecretRegex = "^(?=.*\\d)(?=.*[a-z])(?=.*[A-Z])(?!.*\\s).{14,200}$";

  private Integer clientSecretRegexFlags;

  private String clientNameRegex = "^.{3,75}$";

  private Integer clientNameRegexFlags = Pattern.UNICODE_CHARACTER_CLASS;

  private String scopeNameRegex = "^.{3,50}$";

  private Integer scopeNameRegexFlags = Pattern.UNICODE_CHARACTER_CLASS;

  private String scopeDescriptionRegex = "^.{3,64000}$";

  private Integer scopeDescriptionRegexFlags = Pattern.UNICODE_CHARACTER_CLASS;

  public Pattern getUserNamePattern() {
    return userNameRegexFlags == null ? Pattern.compile(userNameRegex) : Pattern.compile(
        userNameRegex, userNameRegexFlags);
  }

  public Pattern getUserNameExactPattern() {
    return userNameExactRegexFlags == null ? Pattern.compile(userNameExactRegex) : Pattern.compile(
        userNameExactRegex, userNameExactRegexFlags);
  }

  public Pattern getPasswordPattern() {
    return passwordRegexFlags == null ? Pattern.compile(passwordRegex)
        : Pattern.compile(passwordRegex, passwordRegexFlags);
  }

  public Pattern getEmailPattern() {
    return emailRegexFlags == null ? Pattern.compile(emailRegex) : Pattern.compile(
        emailRegex, emailRegexFlags);
  }

  public Pattern getMobilePattern() {
    return mobileRegexFlags == null ? Pattern.compile(mobileRegex) : Pattern.compile(
        mobileRegex, mobileRegexFlags);
  }

  public Pattern getClientIdPattern() {
    return clientIdRegexFlags == null ? Pattern.compile(clientIdRegex) : Pattern.compile(
        clientIdRegex, clientIdRegexFlags);
  }

  public Pattern getClientSecretPattern() {
    return clientSecretRegexFlags == null ? Pattern.compile(clientSecretRegex) : Pattern.compile(
        clientSecretRegex, clientSecretRegexFlags);
  }

  public Pattern getClientNamePattern() {
    return clientNameRegexFlags == null ? Pattern.compile(clientNameRegex) : Pattern.compile(
        clientNameRegex, clientNameRegexFlags);
  }

  public Pattern getScopeNamePattern() {
    return scopeNameRegexFlags == null ? Pattern.compile(scopeNameRegex) : Pattern.compile(
        scopeNameRegex, scopeNameRegexFlags);
  }

  public Pattern getScopeDescriptionPattern() {
    return scopeDescriptionRegexFlags == null ? Pattern.compile(scopeDescriptionRegex) : Pattern
        .compile(scopeDescriptionRegex, scopeDescriptionRegexFlags);
  }

}

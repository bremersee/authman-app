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

package org.bremersee.authman.business;

import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Registration properties.
 *
 * @author Christian Bremer
 */
@ConfigurationProperties("bremersee.registration")
@Component
@Getter
@Setter
@ToString
@EqualsAndHashCode
public class RegistrationProperties {

  /**
   * The life time of a registration request. Default is {@code 30}. If the life time is expired,
   * the email validation link will be no longer valid and the registration won't be complete.
   */
  private long lifeTime = 30L;

  /**
   * The time unit of the life time value. Default is {@link ChronoUnit#DAYS}.
   */
  private ChronoUnit lifeTimeUnit = ChronoUnit.DAYS;

  /**
   * The email validation link. The place holder {@code {registrationHash}} will be replaced by the
   * registration hash.
   */
  private String link = "http://localhost:8080/authman/register?hash={registrationHash}";

  /**
   * The sender of the registration mail. Default is {@code no-reply@bremersee.org}.
   */
  private String sender = "no-reply@bremersee.org";

  /**
   * The message source code of the mail subject.
   */
  private String subjectCode = "userRegistrationService.sendValidationEmail.subject";

  /**
   * Creates a duration object of the registration life time.
   *
   * @return a duration object of the registration life time
   */
  public Duration getLifeTimeDuration() {
    return Duration.of(lifeTime, lifeTimeUnit);
  }

  /**
   * Builds the expiration date from the life time and the current date.
   *
   * @return the expiration date of the registration request
   */
  public Date buildExpirationDate() {
    return new Date(System.currentTimeMillis() + getLifeTimeDuration().toMillis());
  }

}

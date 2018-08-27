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

package org.bremersee.authman;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.bremersee.authman.model.UserProfileCreateRequestDto;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * @author Christian Bremer
 */
@ConfigurationProperties(prefix = "bremersee.startup")
@Getter
@Setter
@ToString
@EqualsAndHashCode
public class StartupProperties {

  /**
   * The administrator profile that will be created at the first startup.
   */
  private UserProfileCreateRequestDto admin = new UserProfileCreateRequestDto();

  private UserProfileCreateRequestDto actuator = new UserProfileCreateRequestDto();

  public StartupProperties() {
    admin.setUserName("admin");
    admin.setPassword("secret4ADMIN");
    admin.setDisplayName("Adam Admin");
    admin.setEmail("admin@bremersee.org");
    admin.setPreferredLocale("de_DE");
    admin.setPreferredTimeZoneId("Europe/Berlin");

    actuator.setUserName("actuator");
    actuator.setPassword("secret4ACTUATOR");
    actuator.setDisplayName("Eva Actuator");
    actuator.setEmail("actuator@bremersee.org");
    actuator.setPreferredLocale("de_DE");
    actuator.setPreferredTimeZoneId("Europe/Berlin");
  }
}

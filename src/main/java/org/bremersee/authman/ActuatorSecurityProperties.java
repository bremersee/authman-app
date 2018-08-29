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

import java.util.ArrayList;
import java.util.List;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.bremersee.authman.security.core.RoleConstants;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * @author Christian Bremer
 */
@ConfigurationProperties(prefix = "bremersee.access")
@Getter
@Setter
@ToString
@EqualsAndHashCode
@NoArgsConstructor
@Slf4j
public class ActuatorSecurityProperties {

  private List<String> ipAddresses = new ArrayList<>();

  @SuppressWarnings("WeakerAccess")
  public String buildAccess() {
    final StringBuilder sb = new StringBuilder();
    sb.append("hasAuthority('").append(RoleConstants.ADMIN_ROLE).append("')");
    sb.append(" or ").append("hasAuthority('").append(RoleConstants.ACTUATOR_ROLE).append("')");
    ipAddresses.forEach(
        ipAddress -> sb.append(" or ").append("hasIpAddress('").append(ipAddress).append("')"));
    final String access = sb.toString();
    log.info("Actuator access = {}", access);
    return access;
  }

}

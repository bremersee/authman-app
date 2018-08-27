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
 * @author Christian Bremer
 */
@ConfigurationProperties("bremersee.mobile-change")
@Component
@Getter
@Setter
@ToString
@EqualsAndHashCode
public class MobileChangeProperties {

  private long lifeTime = 15L;

  private ChronoUnit lifeTimeUnit = ChronoUnit.MINUTES;

  private int hashLength = 6;

  public Duration getLifeTimeDuration() {
    return Duration.of(lifeTime, lifeTimeUnit);
  }

  public Date buildExpirationDate() {
    return new Date(System.currentTimeMillis() + getLifeTimeDuration().toMillis());
  }

}

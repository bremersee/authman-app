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

import lombok.extern.slf4j.Slf4j;
import org.bremersee.smbcon.client.SambaConnectorMock;
import org.bremersee.smbcon.api.SambaConnectorControllerApi;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * @author Christian Bremer
 */
@Configuration
@ConditionalOnProperty(
    prefix = "bremersee.samba-connector",
    name = "name",
    havingValue = "false",
    matchIfMissing = true)
@Slf4j
public class SambaConnectorMockConfiguration {

  @Bean
  public SambaConnectorControllerApi sambaConnector() {
    log.info("Creating samba connector MOCK !!!");
    return new SambaConnectorMock();
  }
}

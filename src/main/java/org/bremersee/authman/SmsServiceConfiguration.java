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

import org.bremersee.sms.DummySmsService;
import org.bremersee.sms.GoyyaSmsService;
import org.bremersee.sms.SmsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * @author Christian Bremer
 */
@Configuration
@EnableConfigurationProperties({SmsServiceProperties.class})
public class SmsServiceConfiguration {

  private final SmsServiceProperties properties;

  @Autowired
  public SmsServiceConfiguration(final SmsServiceProperties properties) {
    this.properties = properties;
  }

  @Bean
  public SmsService smsService() {
    if (!properties.isEnabled()) {
      return new DummySmsService();
    }
    final GoyyaSmsService smsService = new GoyyaSmsService(
        properties.getUsername(),
        properties.getPassword(),
        properties.getUrl());
    smsService.setDefaultSender(properties.getSender());
    return smsService;
  }
}

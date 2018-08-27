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

import com.github.mongobee.Mongobee;
import org.bremersee.authman.domain.changelogs.Placeholder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.mongo.MongoProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.util.StringUtils;

/**
 * @author Christian Bremer
 */
@Configuration
@EnableConfigurationProperties(MongoProperties.class)
public class MongobeeConfiguration {

  private MongoProperties mongoProperties;

  @Autowired
  public MongobeeConfiguration(
      MongoProperties mongoProperties) {
    this.mongoProperties = mongoProperties;
  }

  @Bean
  public Mongobee mongobee(Environment environment) {

    Mongobee runner = new Mongobee(buildMongoUri());
    runner.setChangeLogsScanPackage(
        Placeholder.class.getPackage().getName());
    runner.setSpringEnvironment(environment); // enables profile support
    return runner;
  }

  private String buildMongoUri() {
    final StringBuilder sb = new StringBuilder();

    if (StringUtils.hasText(mongoProperties.getUri())) {

      sb.append(mongoProperties.getUri());
      if (StringUtils.hasText(mongoProperties.getDatabase())
          && !mongoProperties.getUri().contains("/" + mongoProperties.getDatabase())) {
        if (!mongoProperties.getUri().endsWith("/")) {
          sb.append("/");
        }
        sb.append(mongoProperties.getDatabase());
      }

    } else {

      sb.append("mongodb://");
      if (StringUtils.hasText(mongoProperties.getUsername())
          && mongoProperties.getPassword() != null) {
        sb
            .append(mongoProperties.getUsername())
            .append(':')
            .append(mongoProperties.getPassword())
            .append('@');
      }
      sb.append(mongoProperties.getHost());
      sb.append(':');
      if (mongoProperties.getPort() == null) {
        sb.append(MongoProperties.DEFAULT_PORT);
      } else {
        sb.append(mongoProperties.getPort());
      }
      sb
          .append('/')
          .append(mongoProperties.getDatabase());
    }

    return sb.toString();
  }

}

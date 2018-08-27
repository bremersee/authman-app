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

import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;

/**
 * @author Christian Bremer
 */
@Configuration
@EnableResourceServer
public class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {

  @Override
  public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
    // nothing to configure
  }

  @Override
  public void configure(HttpSecurity http) throws Exception {
    // Working config plain
//            http                                                              // NOSONAR
//                    .antMatcher("/api/**")                                    // NOSONAR
//                    .authorizeRequests().anyRequest().authenticated();        // NOSONAR

    // Working config with options allowed
//            http                                                              // NOSONAR
//                    .antMatcher("/api/**").authorizeRequests()                // NOSONAR
//                    .antMatchers(HttpMethod.OPTIONS).permitAll()              // NOSONAR
//                    .anyRequest().authenticated();                            // NOSONAR

    // test config
    http
        .antMatcher("/api/**")
        .authorizeRequests()
        .antMatchers(HttpMethod.OPTIONS).permitAll()
//        .antMatchers(HttpMethod.PUT, "/api/user-registration").permitAll()
//        .antMatchers(HttpMethod.GET, "/api/user-registration/validation/**").permitAll()
        .anyRequest().authenticated();
  }
}

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

import org.bremersee.authman.domain.OAuth2ForeignTokenRepository;
import org.bremersee.authman.domain.RoleRepository;
import org.bremersee.authman.domain.UserProfileRepository;
import org.bremersee.authman.domain.UserRegistrationRequestRepository;
import org.bremersee.authman.security.authentication.OAuth2AuthenticationProvider;
import org.bremersee.authman.security.crypto.password.PasswordEncoderImpl;
import org.bremersee.authman.security.crypto.password.PasswordEncoderProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.GlobalAuthenticationConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * @author Christian Bremer
 */
@Configuration
@EnableConfigurationProperties({PasswordEncoderProperties.class})
public class GlobalAuthenticationConfiguration extends GlobalAuthenticationConfigurerAdapter {

  private final UserProfileRepository userProfileRepository;

  private final UserRegistrationRequestRepository userRegistrationRequestRepository;

  private final RoleRepository roleRepository;

  private final UserDetailsService userDetailsService;

  private final OAuth2ForeignTokenRepository oauth2TokenRepository;

  private final PasswordEncoderImpl passwordEncoder;

  @Autowired
  public GlobalAuthenticationConfiguration(
      final PasswordEncoderProperties passwordEncoderProperties,
      final UserProfileRepository userProfileRepository,
      final UserRegistrationRequestRepository userRegistrationRequestRepository,
      final RoleRepository roleRepository,
      final UserDetailsService userDetailsService,
      final OAuth2ForeignTokenRepository oauth2TokenRepository) {

    this.userProfileRepository = userProfileRepository;
    this.userRegistrationRequestRepository = userRegistrationRequestRepository;
    this.roleRepository = roleRepository;
    this.userDetailsService = userDetailsService;
    this.oauth2TokenRepository = oauth2TokenRepository;
    this.passwordEncoder = new PasswordEncoderImpl(passwordEncoderProperties);
    this.passwordEncoder.init();
  }

  @Override
  public void init(AuthenticationManagerBuilder auth) throws Exception {
    auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);
    auth.authenticationProvider(oAuth2AuthenticationProvider());
  }

  @Bean(name = "passwordEncoder")
  public PasswordEncoderImpl passwordEncoder() {
    return passwordEncoder;
  }

  @Bean("oAuth2AuthenticationProviderAndImporter")
  public OAuth2AuthenticationProvider oAuth2AuthenticationProvider() {

    return new OAuth2AuthenticationProvider(
        userProfileRepository,
        userRegistrationRequestRepository,
        roleRepository,
        oauth2TokenRepository,
        userDetailsService,
        passwordEncoder);
  }

}

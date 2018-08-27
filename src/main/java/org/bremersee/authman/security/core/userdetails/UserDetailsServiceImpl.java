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

package org.bremersee.authman.security.core.userdetails;

import org.bremersee.authman.domain.RoleRepository;
import org.bremersee.authman.domain.UserProfile;
import org.bremersee.authman.domain.UserProfileRepository;
import org.bremersee.utils.PasswordUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * @author Christian Bremer
 */
@Component("userDetailsService")
public class UserDetailsServiceImpl implements UserDetailsService {

  private final UserProfileRepository userProfileRepository;

  private final RoleRepository roleRepository;

  @Autowired
  public UserDetailsServiceImpl(
      UserProfileRepository userProfileRepository,
      RoleRepository roleRepository) {

    this.userProfileRepository = userProfileRepository;
    this.roleRepository = roleRepository;
  }

  /**
   * {@inheritDoc}
   *
   * <p>Returns an {@link User} that is always enabled, non expired and non locked. If the user was
   * created silently during the oauth2 registration process, the user has no password set. Then a
   * random password will be generated so that the user can not log in with user name and password,
   * only with it's social media account.
   *
   * @param userName the user name (can be the email address, too)
   * @return the user
   */
  @Override
  public UserDetails loadUserByUsername(final String userName) {

    final UserProfile userProfile = userProfileRepository
        .findByLogin(userName)
        .orElseThrow(() -> new UsernameNotFoundException(userName + " was not found."));

    return new User(
        userProfile.getUserName(),
        StringUtils.hasText(userProfile.getPassword()) ? userProfile.getPassword()
            : "{clear}" + PasswordUtils.createRandomClearPassword(
                32, false, true),
        userProfile.isEnabled(),
        true,
        true,
        true,
        roleRepository.findGrantedAuthoritiesByUserName(userProfile.getUserName()));
  }
}

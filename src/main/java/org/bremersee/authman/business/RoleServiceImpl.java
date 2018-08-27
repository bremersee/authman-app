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

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;
import javax.validation.constraints.NotNull;
import org.bremersee.authman.domain.Role;
import org.bremersee.authman.domain.RoleRepository;
import org.bremersee.authman.listener.UserProfileListener;
import org.bremersee.authman.security.core.RoleConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

/**
 * @author Christian Bremer
 */
@Component
public class RoleServiceImpl implements RoleService {

  private final RoleRepository roleRepository;

  private final UserProfileListener userProfileListener;

  @Autowired
  public RoleServiceImpl(
      final RoleRepository roleRepository,
      final UserProfileListener userProfileListener) {
    this.roleRepository = roleRepository;
    this.userProfileListener = userProfileListener;
  }

  @Override
  public Set<String> getAvailableUserRoles() {
    return new LinkedHashSet<>(Arrays.asList(RoleConstants.USER_ROLES));
  }

  @Override
  public Set<String> getAvailableOAuth2ClientRoles() {
    return new LinkedHashSet<>(Arrays.asList(RoleConstants.OAUTH2_CLIENT_ROLES));
  }

  @Override
  public boolean hasRole(@NotNull final String userName, @NotNull final String roleName) {
    return roleRepository.countByRoleNameAndUserName(roleName, userName) > 0;
  }

  @Override
  public Set<String> getRoles(@NotNull final String userName) {
    return roleRepository.findRoleNamesByUserName(userName);
  }

  @Override
  public Set<GrantedAuthority> getGrantedAuthorities(@NotNull final String userName) {
    return roleRepository.findGrantedAuthoritiesByUserName(userName);
  }

  @Override
  public void deleteRole(@NotNull final String userName, @NotNull final String roleName) {
    roleRepository.deleteByRoleNameAndUserName(roleName, userName);
    userProfileListener.onNewRoles(userName, getRoles(userName));
  }

  @Override
  public void deleteRoles(@NotNull final String userName) {
    roleRepository.deleteByUserName(userName);
    userProfileListener.onNewRoles(userName, Collections.emptySet());
  }

  @Override
  public void addRole(@NotNull final String userName, @NotNull final String roleName) {
    if (roleRepository.countByRoleNameAndUserName(roleName, userName) == 0) {
      roleRepository.save(new Role(roleName, userName));
      userProfileListener.onNewRoles(userName, getRoles(userName));
    }
  }

  @Override
  public void setRoles(@NotNull final String userName, @NotNull final Collection<String> roleNames) {
    final Set<String> newRoles = new HashSet<>(roleNames);
    roleRepository.findRoleNamesByUserName(userName).forEach(roleName -> {
      if (!newRoles.contains(roleName)) {
        roleRepository.deleteByRoleNameAndUserName(roleName, userName);
      }
    });
    newRoles.forEach(roleName -> {
      if (roleRepository.countByRoleNameAndUserName(roleName, userName) == 0) {
        roleRepository.save(new Role(roleName, userName));
      }
    });
    userProfileListener.onNewRoles(userName, getRoles(userName));
  }
}

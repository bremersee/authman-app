/*
 * Copyright 2016 the original author or authors.
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

package org.bremersee.authman.security.core;

import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;
import javax.validation.constraints.NotNull;
import org.apache.commons.lang3.Validate;
import org.bremersee.authman.security.core.context.RunAsAuthentication;
import org.bremersee.authman.security.core.context.RunAsCallback;
import org.bremersee.authman.security.core.context.RunAsCallbackWithoutResult;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * @author Christian Bremer
 */
public interface SecurityHelper {

  static boolean isCurrentUserName(String userName) {
    return userName != null && userName.equals(getCurrentUserName());
  }

  static String getCurrentUserName() {
    final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    return authentication == null ? null : authentication.getName();
  }

  static Set<String> getCurrentUserRoles() {
    final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    return authentication == null ? Collections.emptySet() : authentication.getAuthorities()
        .stream()
        .map(GrantedAuthority::getAuthority)
        .collect(Collectors.toSet());
  }

  static boolean currentUserHasRole(@NotNull String role) {
    return getCurrentUserRoles().contains(role);
  }

  static boolean isCurrentUserAdmin() {
    return getCurrentUserRoles().contains(RoleConstants.ADMIN_ROLE);
  }

  /**
   * Executes the callback with the specified authority (name and roles).
   *
   * @param name     the name of the executing authority
   * @param roles    the roles of the executing authority
   * @param callback the callback which should be executed
   * @param <T>      the response type
   * @return the response of the callback
   */
  static <T> T runAs(final String name, final String[] roles, final RunAsCallback<T> callback) {
    Validate.notBlank(name, "Name mast not be null or blank");
    final Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    try {
      SecurityContextHolder.getContext().setAuthentication(new RunAsAuthentication(name, roles));
      return callback.execute();
    } finally {
      SecurityContextHolder.getContext().setAuthentication(auth);
    }
  }

  /**
   * Executes the callback with the specified authority (name and roles).
   *
   * @param name     the name of the executing authority
   * @param roles    the roles of the executing authority
   * @param callback the callback which should be executed
   */
  static void runAsWithoutResult(final String name, final String[] roles,
      final RunAsCallbackWithoutResult callback) {
    runAs(name, roles, callback);
  }

}

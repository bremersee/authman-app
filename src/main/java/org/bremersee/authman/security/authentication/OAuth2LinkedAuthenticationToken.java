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

package org.bremersee.authman.security.authentication;

import java.io.Serializable;
import java.util.Collection;
import java.util.LinkedHashSet;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
import org.bremersee.authman.domain.UserProfile;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * A successfully linked authentication token. It will be returned by {@link
 * OAuth2AuthenticationProvider}, if the authentication was successful and the accounts are linked.
 * {@link OAuth2LinkedAuthenticationToken#isAuthenticated()} returns {@code true} per default.
 *
 * @author Christian Bremer
 */
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
class OAuth2LinkedAuthenticationToken extends AbstractAuthenticationToken {

  @Getter
  private final OAuth2AuthenticationToken originalOAuth2AuthenticationToken;

  private final Serializable principal;

  OAuth2LinkedAuthenticationToken(
      final OAuth2AuthenticationToken originalOAuth2AuthenticationToken,
      final UserProfile userProfile,
      final Collection<GrantedAuthority> roles) {

    super(createGrantedAuthorities(originalOAuth2AuthenticationToken, roles));
    this.originalOAuth2AuthenticationToken = originalOAuth2AuthenticationToken;
    this.principal = userProfile;
    setAuthenticated(true);
  }

  OAuth2LinkedAuthenticationToken(
      final OAuth2AuthenticationToken originalOAuth2AuthenticationToken,
      final UserDetails userDetails) {

    super(createGrantedAuthorities(originalOAuth2AuthenticationToken, userDetails));
    this.originalOAuth2AuthenticationToken = originalOAuth2AuthenticationToken;
    this.principal = userDetails;
    setAuthenticated(true);
  }

  @Override
  public CodeExchangeResponse getCredentials() {
    return originalOAuth2AuthenticationToken.getCredentials();
  }

  /**
   * Returns a {@link UserProfile} or {@link UserDetails}.
   *
   * @return the principal
   */
  @Override
  public Serializable getPrincipal() {
    return principal;
  }

  private static Collection<GrantedAuthority> createGrantedAuthorities(
      final OAuth2AuthenticationToken originalOAuth2AuthenticationToken,
      final Collection<GrantedAuthority> roles) {

    final LinkedHashSet<GrantedAuthority> authorities = new LinkedHashSet<>();
    if (originalOAuth2AuthenticationToken.getAuthorities() != null) {
      authorities.addAll(originalOAuth2AuthenticationToken.getAuthorities());
    }
    if (roles != null) {
      authorities.addAll(roles);
    }
    return authorities;
  }

  private static Collection<GrantedAuthority> createGrantedAuthorities(
      final OAuth2AuthenticationToken originalOAuth2AuthenticationToken,
      final UserDetails userDetails) {

    final LinkedHashSet<GrantedAuthority> authorities = new LinkedHashSet<>();
    if (originalOAuth2AuthenticationToken.getAuthorities() != null) {
      authorities.addAll(originalOAuth2AuthenticationToken.getAuthorities());
    }
    if (userDetails.getAuthorities() != null) {
      authorities.addAll(userDetails.getAuthorities());
    }
    return authorities;
  }

}

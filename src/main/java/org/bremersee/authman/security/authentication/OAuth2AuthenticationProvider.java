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

import java.util.HashSet;
import java.util.Optional;
import java.util.Random;
import java.util.Set;
import java.util.stream.Collectors;
import javax.validation.constraints.NotNull;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bremersee.authman.domain.OAuth2ForeignToken;
import org.bremersee.authman.domain.OAuth2ForeignTokenRepository;
import org.bremersee.authman.domain.Role;
import org.bremersee.authman.domain.RoleRepository;
import org.bremersee.authman.domain.UserProfile;
import org.bremersee.authman.domain.UserProfileRepository;
import org.bremersee.authman.domain.UserRegistrationRequestRepository;
import org.bremersee.authman.mapper.OAuth2ForeignTokenMapper;
import org.bremersee.authman.mapper.OAuth2ForeignTokenMapperImpl;
import org.bremersee.authman.security.core.RoleConstants;
import org.bremersee.authman.security.crypto.password.PasswordEncoder;
import org.bremersee.utils.PasswordUtils;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * @author Christian Bremer
 */
@RequiredArgsConstructor
@Slf4j
public class OAuth2AuthenticationProvider implements AuthenticationProvider {

  private static final String REDIRECT_TO_ERROR_LOG_STATEMENT = "Create account, link and "
      + "authenticate: {} Redirection to /merge?error={}";

  @NonNull
  private final UserProfileRepository userProfileRepository;

  @NonNull
  private final UserRegistrationRequestRepository userRegistrationRequestRepository;

  @NonNull
  private final RoleRepository roleRepository;

  @NonNull
  private final OAuth2ForeignTokenRepository oauth2TokenRepository;

  @NonNull
  private final UserDetailsService userDetailsService;

  @NonNull
  private final PasswordEncoder passwordEncoder;

  private OAuth2ForeignTokenMapper foreignTokenMapper = new OAuth2ForeignTokenMapperImpl();

  @SuppressWarnings("unused")
  public void setForeignTokenMapper(
      final OAuth2ForeignTokenMapper foreignTokenMapper) {
    if (foreignTokenMapper != null) {
      this.foreignTokenMapper = foreignTokenMapper;
    }
  }

  @Override
  public Authentication authenticate(@NotNull final Authentication authentication) {

    Assert.notNull(authentication, "Authentication must not be null.");
    Assert.isTrue(authentication instanceof OAuth2AuthenticationToken,
        "Authentication must be of type " + OAuth2AuthenticationToken.class.getName());

    if (authentication instanceof OAuth2CreateAccountSilentlyAndLinkAuthenticationToken) {
      log.debug("Authentication is an 'OAuth2CreateAccountSilentlyAndLinkAuthenticationToken': " +
          "Trying to create an account silently and link it.");
      return createAccountSilentlyAndLinkAndAuthenticate(
          (OAuth2CreateAccountSilentlyAndLinkAuthenticationToken) authentication);
    }

    if (authentication instanceof OAuth2CreateAccountAndLinkAuthenticationToken) {
      log.debug("Authentication is an 'OAuth2CreateAccountAndLinkAuthenticationToken': " +
          "Trying to create an account and link it.");
      return createAccountAndLinkAndAuthenticate(
          (OAuth2CreateAccountAndLinkAuthenticationToken) authentication);
    }

    if (authentication instanceof OAuth2LinkAuthenticationToken) {
      log.debug("Authentication is an 'OAuth2LinkAuthenticationToken': " +
          "Trying to authenticate with username and password and link the accounts.");
      return linkAndAuthenticate((OAuth2LinkAuthenticationToken) authentication);
    }

    log.debug("Authentication is an 'OAuth2AuthenticationToken': "
        + "Trying to authenticate or redirecting to /merge");
    return authenticateOrRedirect((OAuth2AuthenticationToken) authentication);
  }

  @Override
  public boolean supports(final Class<?> authentication) {
    boolean result = OAuth2AuthenticationToken.class.isAssignableFrom(authentication);
    log.debug("Supports {}? {}", authentication.getSimpleName(), result);
    return result;
  }

  // ***********************************************************************************************
  // Base methods
  // ***********************************************************************************************

  private Authentication authenticateOrRedirect(final OAuth2AuthenticationToken authentication) {

    OAuth2ForeignToken foreignToken = findForeignToken(authentication)
        .orElse(new OAuth2ForeignToken());

    foreignTokenMapper.updateForeignToken(foreignToken, authentication);

    if (StringUtils.hasText(foreignToken.getUserName())) {
      foreignToken = saveForeignToken(foreignToken);
      log.debug("Authenticate or redirect: Successfully authenticated.");
      return new OAuth2LinkedAuthenticationToken(authentication,
          userDetailsService.loadUserByUsername(foreignToken.getUserName()));
    }

    final String loginName = authentication.getPrincipal().getEmail();
    if (!StringUtils.hasText(loginName)) {
      throw new OAuth2MustBeLinkedException(
          "User of " + authentication.getProvider() + " with name " +
              authentication.getPrincipal().getName() +
              " must link it's account with a local one.", authentication);
    }

    final UserProfile userProfile = userProfileRepository
        .findByLogin(loginName)
        .orElseThrow(() -> new OAuth2MustBeLinkedException(
            "User of " + authentication.getProvider() + " with name " +
                authentication.getPrincipal().getName() +
                " must link it's account with a local one.",
            authentication));

    foreignToken.setUserName(userProfile.getUserName());
    saveForeignToken(foreignToken);
    log.debug("Authenticate or redirect: Successfully authenticated by login/email [{}].",
        loginName);

    if (updateUserProfile(userProfile, authentication.getPrincipal())) {
      userProfileRepository.save(userProfile);
    }

    return new OAuth2LinkedAuthenticationToken(
        authentication,
        userProfile,
        roleRepository.findGrantedAuthoritiesByUserName(userProfile.getUserName()));
  }

  private Authentication linkAndAuthenticate(final OAuth2LinkAuthenticationToken authentication) {
    validateLinkAuthenticationToken(authentication);
    final UserDetails user;
    try {
      user = userDetailsService.loadUserByUsername(authentication.getUserName());

    } catch (final UsernameNotFoundException nfe) {
      final String msg = String.format("User [%s] was not found.", authentication.getUserName());
      final OAuth2LinkException e = new OAuth2LinkException(msg, nfe,
          OAuth2LinkException.Reason.LOGIN_FAILED);
      log.debug("Link and authenticate: {} Redirecting to /merge?error={}", msg, e.getReason());
      throw e;
    }

    if (passwordEncoder.matches(authentication.getPassword(), user.getPassword())) {
      final OAuth2ForeignToken foreignToken = findForeignToken(authentication)
          .orElse(new OAuth2ForeignToken());
      foreignTokenMapper.updateForeignToken(foreignToken, authentication);
      foreignToken.setUserName(user.getUsername());
      saveForeignToken(foreignToken);

      userProfileRepository.findByUserName(user.getUsername()).ifPresent(
          userProfile -> {
            if (updateUserProfile(userProfile, authentication.getPrincipal())) {
              userProfileRepository.save(userProfile);
            }
          });

      log.debug("Link and authenticate: " +
          "Successfully linked and authenticated by username and password.");
      return new OAuth2LinkedAuthenticationToken(authentication, user);
    }

    final String msg = String.format("Passwords of user [%s] don't match.", user.getUsername());
    OAuth2LinkException e = new OAuth2LinkException(msg,
        OAuth2LinkException.Reason.LOGIN_FAILED); // PASSWORDS_DO_NOT_MATCH
    log.debug("Link and authenticate: {} Redirecting to /merge?error={}", msg, e.getReason());
    throw e;
  }

  private Authentication createAccountAndLinkAndAuthenticate(
      final OAuth2CreateAccountAndLinkAuthenticationToken authentication) {

    validateCreateAccountAndLinkAuthenticationToken(authentication);

    final UserProfile userProfile = createAndSaveNewUserProfile(authentication);
    final OAuth2ForeignToken foreignToken = findForeignToken(authentication)
        .orElse(new OAuth2ForeignToken());
    foreignTokenMapper.updateForeignToken(foreignToken, authentication);
    foreignToken.setUserName(authentication.getUserName());
    saveForeignToken(foreignToken);

    log.debug("Create account, link and authenticate: Successfully created account, "
        + "linked and authenticated.");
    return new OAuth2LinkedAuthenticationToken(authentication, userProfile,
        roleRepository.findGrantedAuthoritiesByUserName(userProfile.getUserName()));
  }

  private Authentication createAccountSilentlyAndLinkAndAuthenticate(
      final OAuth2CreateAccountSilentlyAndLinkAuthenticationToken authentication) {

    final OAuth2CreateAccountAndLinkAuthenticationToken createToken = generateCreateAndLinkAccountToken(
        authentication);
    try {
      Authentication result = createAccountAndLinkAndAuthenticate(createToken);
      log.debug("Successfully created account silently, linked and authenticated.");
      return result;

    } catch (OAuth2CreateAndLinkException e) {
      log.debug("Create account silently, link and authenticate: {} - Redirect to /login?error");
      throw new OAuth2AuthenticationException("Creating user silently failed.", e);
    }
  }

  // ***********************************************************************************************
  // Helper methods
  // ***********************************************************************************************

  private Optional<OAuth2ForeignToken> findForeignToken(
      @NotNull final OAuth2AuthenticationToken authentication) {

    final String provider = authentication.getProvider();
    final String foreignUserName = authentication.getPrincipal().getName();
    log.debug("Looking for saved foreign token of provider [{}] and foreign username [{}] ...",
        provider, foreignUserName);
    return oauth2TokenRepository.findByProviderAndForeignUserName(provider, foreignUserName);
  }

  private OAuth2ForeignToken saveForeignToken(@NotNull final OAuth2ForeignToken foreignToken) {
    return oauth2TokenRepository.save(foreignToken);
  }

  private void validateLinkAuthenticationToken(final OAuth2LinkAuthenticationToken authentication) {
    if (!StringUtils.hasText(authentication.getUserName())) {
      final OAuth2LinkException e = new OAuth2LinkException("Username must be present.",
          OAuth2LinkException.Reason.LOGIN_FAILED);
      log.debug("Link and authenticate: {} Redirection to /merge?error={}",
          e.getMessage(), e.getReason());
      throw e;
    }
    if (!StringUtils.hasText(authentication.getPassword())) {
      final OAuth2LinkException e = new OAuth2LinkException("Password must be present.",
          OAuth2LinkException.Reason.LOGIN_FAILED);
      log.debug("Link and authenticate: {} Redirection to /merge?error={}",
          e.getMessage(), e.getReason());
      throw e;
    }
  }

  private void validateCreateAccountAndLinkAuthenticationToken(
      final OAuth2CreateAccountAndLinkAuthenticationToken authentication) {

    if (!StringUtils.hasText(authentication.getUserName())) {
      OAuth2CreateAndLinkException e = new OAuth2CreateAndLinkException("Username must be present.",
          OAuth2CreateAndLinkException.Reason.BAD_USER_NAME);
      log.debug(REDIRECT_TO_ERROR_LOG_STATEMENT, e.getMessage(), e.getReason());
      throw e;
    }
    if (!StringUtils.hasText(authentication.getPassword())) {
      OAuth2CreateAndLinkException e = new OAuth2CreateAndLinkException("Password must be present.",
          OAuth2CreateAndLinkException.Reason.PASSWORD_TOO_WEAK);
      log.debug(REDIRECT_TO_ERROR_LOG_STATEMENT, e.getMessage(), e.getReason());
      throw e;
    }
    if (!authentication.getPassword().equals(authentication.getPasswordRepetition())) {
      OAuth2CreateAndLinkException e = new OAuth2CreateAndLinkException("Passwords are not equal.",
          OAuth2CreateAndLinkException.Reason.PASSWORDS_ARE_NOT_EQUAL);
      log.debug(REDIRECT_TO_ERROR_LOG_STATEMENT, e.getMessage(), e.getReason());
      throw e;
    }
  }

  private OAuth2CreateAccountAndLinkAuthenticationToken generateCreateAndLinkAccountToken(
      final OAuth2AuthenticationToken authToken) {

    final String userName = generateUniqueUserName();
    final String password = PasswordUtils.createRandomClearPassword(
        14, false, true);
    return new OAuth2CreateAccountAndLinkAuthenticationToken(authToken, userName, password,
        password);
  }

  private String generateUniqueUserName() {
    String userName = generateUserName();
    while (userProfileRepository.countByUserName(userName) > 0
        || userRegistrationRequestRepository.countByUserName(userName) > 0) {
      userName = generateUserName();
    }
    return userName;
  }

  private String generateUserName() {
    final Random random = new Random();
    String n = String.valueOf(random.nextInt());
    while (n.length() < 7) {
      n = String.valueOf(random.nextInt());
    }
    return "u" + n.substring(0, 7);
  }

  private UserProfile createAndSaveNewUserProfile(
      final OAuth2CreateAccountAndLinkAuthenticationToken authentication) {

    final ForeignUserProfile foreignUserProfile = authentication.getPrincipal();
    UserProfile userProfile = userProfileRepository
        .findByUserName(authentication.getUserName()).orElse(new UserProfile());
    updateUserProfile(userProfile, foreignUserProfile);
    userProfile.setUserName(authentication.getUserName());
    userProfile.setPassword(passwordEncoder.encode(authentication.getPassword()));
    userProfile = userProfileRepository.save(userProfile);

    final Set<String> roleNames = new HashSet<>();
    if (authentication.getAuthorities() != null) {
      roleNames.addAll(
          authentication.getAuthorities()
              .stream()
              .map(GrantedAuthority::getAuthority)
              .collect(Collectors.toSet()));
    }
    roleNames.add(RoleConstants.USER_ROLE);
    for (final String roleName : roleNames) {
      final Role role = roleRepository
          .findByRoleNameAndUserName(roleName, authentication.getUserName())
          .orElse(new Role(roleName, authentication.getUserName()));
      if (role.isNew()) {
        roleRepository.save(role);
      }
    }

    return userProfile;
  }

  private boolean updateUserProfile( // NOSONAR
      final UserProfile destination,
      final ForeignUserProfile source) {

    boolean hasChanged = false;

    if (StringUtils.hasText(source.getName())
        && !StringUtils.hasText(destination.getUserName())) {
      destination.setUserName(source.getName());
      hasChanged = true;
    }
    if (StringUtils.hasText(source.getDisplayName())
        && !StringUtils.hasText(destination.getDisplayName())) {
      destination.setDisplayName(source.getDisplayName());
      hasChanged = true;
    }
    if (StringUtils.hasText(source.getEmail())
        && !StringUtils.hasText(destination.getEmail())) {
      destination.setEmail(source.getEmail());
      hasChanged = true;
    }
    if (source.getTimeZone() != null) {
      destination.setPreferredTimeZoneId(source.getTimeZone().getID());
      hasChanged = true;
    }
    if (source.getLocale() != null) {
      final String newLocaleStr = source.getLocale().toString();
      if (newLocaleStr.length() >= 5) {
        destination.setPreferredLocale(newLocaleStr);
        hasChanged = true;
      } else {
        final String oldLocaleStr = destination.getPreferredLocale();
        if (!StringUtils.hasText(oldLocaleStr)) {
          destination.setPreferredLocale(newLocaleStr);
          hasChanged = true;
        } else {
          final String newLang = source.getLocale().getLanguage();
          final String oldLang = oldLocaleStr.substring(0, 2);
          if (!newLang.equals(oldLang) || newLocaleStr.length() >= oldLocaleStr.length()) {
            destination.setPreferredLocale(newLocaleStr);
            hasChanged = true;
          }
        }
      }
    }

    return hasChanged;
  }

}

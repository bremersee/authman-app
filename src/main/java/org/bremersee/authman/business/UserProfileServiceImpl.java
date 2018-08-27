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

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.stream.Collectors;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import lombok.extern.slf4j.Slf4j;
import org.bremersee.authman.domain.UserProfile;
import org.bremersee.authman.domain.UserProfileRepository;
import org.bremersee.authman.exception.EmailAlreadyExistsException;
import org.bremersee.authman.exception.InvalidEmailException;
import org.bremersee.authman.exception.InvalidMobileException;
import org.bremersee.authman.exception.NotFoundException;
import org.bremersee.authman.exception.PasswordsNotMatchException;
import org.bremersee.authman.listener.UserProfileListener;
import org.bremersee.authman.mapper.UserProfileMapper;
import org.bremersee.authman.model.SambaSettingsDto;
import org.bremersee.authman.model.UserProfileCreateRequestDto;
import org.bremersee.authman.model.UserProfileDto;
import org.bremersee.authman.security.core.RoleConstants;
import org.bremersee.authman.security.core.SecurityHelper;
import org.bremersee.authman.security.crypto.password.PasswordEncoder;
import org.bremersee.authman.validation.ValidationProperties;
import org.bremersee.smbcon.model.Name;
import org.bremersee.smbcon.model.SambaUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.domain.Sort.Direction;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * @author Christian Bremer
 */
@Component
@Slf4j
public class UserProfileServiceImpl extends AbstractUserProfileService
    implements UserProfileService {

  private final UserProfileMapper userMapper;

  private final RoleService roleService;

  private final PasswordEncoder passwordEncoder;

  private final SambaConnectorService sambaConnectorService;

  private final UserProfileListener userProfileListener;

  private int minSearchLength = 3;

  @Autowired
  public UserProfileServiceImpl(
      ValidationProperties validationProperties,
      UserProfileRepository userRepository,
      UserProfileMapper userMapper,
      RoleService roleService,
      PasswordEncoder passwordEncoder,
      SambaConnectorService sambaConnectorService,
      UserProfileListener userProfileListener) {

    super(validationProperties, userRepository);
    this.userMapper = userMapper;
    this.roleService = roleService;
    this.passwordEncoder = passwordEncoder;
    this.sambaConnectorService = sambaConnectorService;
    this.userProfileListener = userProfileListener;
  }

  @Value("${bremersee.user-service.min-search-length:3}")
  public void setMinSearchLength(int minSearchLength) {
    this.minSearchLength = minSearchLength;
  }

  @PreAuthorize("hasRole('ROLE_ADMIN')")
  @Override
  public UserProfileDto createUserProfile(
      @NotNull final UserProfileCreateRequestDto request,
      final boolean isPasswordEncrypted,
      final boolean sendNotification) {

    log.info("Creating user profile [request = {}, isPasswordEncrypted = {}].",
        request, isPasswordEncrypted);

    validateUserProfileCreateRequest(request);

    UserProfile user = new UserProfile();
    user.setDisplayName(request.getDisplayName());
    user.setEmail(request.getEmail());
    if (isPasswordEncrypted) {
      user.setPassword(request.getPassword());
    } else {
      user.setPassword(passwordEncoder.encode(request.getPassword()));
    }
    user.setPreferredLocale(request.getPreferredLocale());
    user.setPreferredTimeZoneId(request.getPreferredTimeZoneId());
    user.setUserName(request.getUserName());
    user.setEnabled(true);
    user.setSambaSettings(request.getSambaSettings());

    if (!isPasswordEncrypted && request.getSambaSettings() != null) {
      sambaConnectorService.addSambaUserAsync(user, request.getPassword());
    }

    user = getUserRepository().save(user);

    final Set<String> roles = new LinkedHashSet<>();
    roles.add(RoleConstants.USER_ROLE);
    roleService.setRoles(user.getUserName(), roles);

    if (sendNotification && !isPasswordEncrypted) {
      // TODO
    }

    final UserProfileDto result = userMapper.mapToDto(user);
    log.info("User profile successfully created: {}", result);
    userProfileListener.onCreateUserProfile(
        result,
        isPasswordEncrypted ? null : request.getPassword(),
        roles);
    return result;
  }

  @Override
  public Page<UserProfileDto> getUserProfiles(final String search, final Pageable pageable) {
    log.info("Getting user profiles [search = {}, pageable = {}].", search, pageable);
    final String s = search == null ? "" : search.trim();
    if (SecurityHelper.isCurrentUserAdmin() || (s.length() >= minSearchLength)) {
      return findUserProfilesBySearch(s, pageable).map(userMapper::mapToDto);
    }
    log.warn("A normal user can only search user profile entries with a search string longer than "
        + minSearchLength + " character(s). Returning an empty page.");
    return new PageImpl<>(Collections.emptyList());
  }

  private Page<UserProfile> findUserProfilesBySearch(final String search, final Pageable pageable) {
    final Pageable p = pageable != null ? pageable : PageRequest
        .of(0, Integer.MAX_VALUE, Sort.by(Direction.ASC, "userName"));
    if (StringUtils.hasText(search)) {
      return getUserRepository().findBySearchRegex(search, p);
    }
    return getUserRepository().findAll(p);
  }

  @PreAuthorize("hasRole('ROLE_ADMIN') or authentication.name == #userName")
  @Override
  public UserProfileDto getUserProfile(@NotNull final String userName) {
    log.info("Getting user profile [{}].", userName);
    return getUserRepository()
        .findByUserName(userName)
        .map(userProfile -> {
          if (SecurityHelper.isCurrentUserAdmin()
              && sambaConnectorService.userExists(userProfile.getUserName())) {
            final SambaUser sambaUser = sambaConnectorService.getUser(userProfile.getUserName());
            SambaSettingsDto sambaSettings = new SambaSettingsDto();
            if (sambaUser.getGroups() != null) {
              sambaSettings.getSambaGroups().addAll(sambaUser
                  .getGroups()
                  .stream()
                  .map(Name::getValue)
                  .collect(Collectors.toList()));
            }
            userProfile.setSambaSettings(sambaSettings);
          }
          return userProfile;
        })
        .map(userMapper::mapToDto)
        .orElseThrow(NotFoundException::new);
  }

  @Override
  public boolean isUserProfileExisting(@NotNull final String userName) {
    final boolean exists = getUserRepository().countByUserName(userName) > 0;
    log.info("User [{}] exists? {}", userName, exists);
    return exists;
  }

  @PreAuthorize("hasRole('ROLE_ADMIN') or authentication.name == #userName")
  @Override
  public UserProfileDto updateUserProfile(
      @NotNull final String userName,
      @NotNull final UserProfileDto userProfile) {

    log.info("Updating user profile [{}] with {}", userName, userProfile);
    UserProfile entity = getUserRepository()
        .findByUserName(userName)
        .orElseThrow(NotFoundException::new);

    validatePreferredLocale(userProfile.getPreferredLocale());
    validatePreferredTimeZone(userProfile.getPreferredTimeZoneId());

    if (SecurityHelper.isCurrentUserAdmin()) {
      if (StringUtils.hasText(userProfile.getEmail()) && !userProfile.getEmail()
          .equals(entity.getEmail())) {
        validateEmail(userProfile.getEmail());
      }
      if (StringUtils.hasText(userProfile.getMobile()) && !userProfile.getMobile()
          .equals(entity.getMobile())) {
        if (!getValidationProperties().getMobilePattern().matcher(userProfile.getMobile())
            .matches()) {
          throw new InvalidMobileException(userProfile.getMobile());
        }
        getUserRepository().findByMobile(userProfile.getMobile()).ifPresent(up -> {
          up.setMobile(null);
          getUserRepository().save(up);
        });
      }

    }
    userMapper.updateEntity(userProfile, entity);
    entity = getUserRepository().save(entity);
    sambaConnectorService.updateSambaUserAsync(entity);
    final UserProfileDto result = userMapper.mapToDto(entity);
    log.info("User profile successfully updated: {}", result);
    userProfileListener.onChangeUserProfile(result);
    return result;
  }

  @PreAuthorize("hasRole('ROLE_ADMIN') or authentication.name == #userName")
  @Override
  public void deleteUserProfile(@NotNull final String userName) {
    log.info("Deleting user profile [{}].", userName);
    roleService.deleteRoles(userName);
    getUserRepository().deleteByUserName(userName);
    sambaConnectorService.deleteUserAsync(userName);
    userProfileListener.onDeleteUserProfile(userName);
  }

  @PreAuthorize("hasRole('ROLE_ADMIN')")
  @Override
  public void enableUser(@NotNull final String userName, final boolean isEnabled) {
    log.info("{} user [{}].", (isEnabled ? "Enabling" : "Disabling"), userName);
    getUserRepository().findByUserName(userName).ifPresent(userProfile -> {
      userProfile.setEnabled(isEnabled);
      final UserProfile savedUserProfile = getUserRepository().save(userProfile);
      sambaConnectorService.updateSambaUserAsync(savedUserProfile);
      userProfileListener.onChangeEnabledState(userName, isEnabled);
    });
  }

  @PreAuthorize("hasRole('ROLE_ADMIN') or authentication.name == #userName")
  @Override
  public boolean isPasswordPresent(@NotNull final String userName) {
    return StringUtils.hasText(
        getUserRepository()
            .findByUserName(userName)
            .orElseThrow(NotFoundException::new)
            .getPassword());
  }

  @PreAuthorize("hasRole('ROLE_ADMIN') or authentication.name == #userName")
  @Override
  public UserProfileDto resetPassword(
      @NotNull final String userName,
      @NotBlank final String newPassword) {
    return changePassword(userName, null, newPassword);
  }

  @PreAuthorize("hasRole('ROLE_ADMIN') or authentication.name == #userName")
  @Override
  public UserProfileDto changePassword(
      @NotNull final String userName,
      final String oldPassword,
      @NotBlank final String newPassword) {

    UserProfile userProfile = getUserRepository()
        .findByLogin(userName)
        .orElseThrow(NotFoundException::new);

    if (!SecurityHelper.isCurrentUserAdmin()
        && StringUtils.hasText(userProfile.getPassword())
        && !passwordEncoder.matches(oldPassword, userProfile.getPassword())) {
      throw new PasswordsNotMatchException();
    }

    if (!SecurityHelper.isCurrentUserAdmin()) {
      validatePassword(newPassword);
    }

    userProfile.setPassword(passwordEncoder.encode(newPassword));
    userProfile = getUserRepository().save(userProfile);
    sambaConnectorService.updateUserPasswordAsync(userName, newPassword);
    userProfileListener.onNewPassword(userName, newPassword);
    return userMapper.mapToDto(userProfile);
  }

  @PreAuthorize("hasRole('ROLE_ADMIN') or authentication.name == #userName")
  @Override
  public void changeEmail(@NotNull String userName, @NotNull String email) {
    UserProfile userProfile = getUserRepository()
        .findByUserName(userName)
        .orElseThrow(NotFoundException::new);
    if (!StringUtils.hasText(email)
        || !getValidationProperties().getEmailPattern().matcher(email).matches()) {
      throw new InvalidEmailException(email);
    }
    if (getUserRepository().countByEmail(email) > 0) {
      throw new EmailAlreadyExistsException(email);
    }
    userProfile.setEmail(email);
    final UserProfile savedUserProfile = getUserRepository().save(userProfile);
    sambaConnectorService.updateSambaUserAsync(savedUserProfile);
    userProfileListener.onNewPassword(userName, email);
  }

  @PreAuthorize("hasRole('ROLE_ADMIN') or authentication.name == #userName")
  @Override
  public void changeMobile(@NotNull final String userName, @NotNull final String mobile) {
    getUserRepository()
        .findByMobile(mobile)
        .ifPresent(userProfile -> {
          if (!userName.equals(userProfile.getUserName())) {
            userProfile.setMobile(null);
            getUserRepository().save(userProfile);
            userProfileListener.onDeleteMobile(userProfile.getUserName(), userProfile.getMobile());
          }
        });

    UserProfile userProfile = getUserRepository()
        .findByUserName(userName)
        .orElseThrow(NotFoundException::new);
    userProfile.setMobile(mobile);
    final UserProfile savedUserProfile = getUserRepository().save(userProfile);
    sambaConnectorService.updateSambaUserAsync(savedUserProfile);
    userProfileListener.onNewMobile(userName, mobile);
  }

}

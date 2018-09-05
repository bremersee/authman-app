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

package org.bremersee.authman.controller.admin;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import javax.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.bremersee.authman.business.OAuth2ForeignTokenService;
import org.bremersee.authman.business.RoleService;
import org.bremersee.authman.business.SambaConnectorService;
import org.bremersee.authman.business.UserProfileService;
import org.bremersee.authman.controller.RedirectMessage;
import org.bremersee.authman.controller.RedirectMessageType;
import org.bremersee.authman.exception.EmailAlreadyExistsException;
import org.bremersee.authman.exception.InvalidEmailException;
import org.bremersee.authman.exception.InvalidLocaleException;
import org.bremersee.authman.exception.InvalidMobileException;
import org.bremersee.authman.exception.InvalidTimeZoneException;
import org.bremersee.authman.model.SelectOptionDto;
import org.bremersee.authman.model.UserProfileDto;
import org.bremersee.authman.security.authentication.facebook.FacebookAuthenticationProperties;
import org.bremersee.authman.security.authentication.github.GitHubAuthenticationProperties;
import org.bremersee.authman.security.authentication.google.GoogleAuthenticationProperties;
import org.bremersee.authman.security.core.RoleConstants;
import org.bremersee.authman.validation.ValidationProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.util.StringUtils;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * @author Christian Bremer
 */
@Controller
@EnableConfigurationProperties({
    FacebookAuthenticationProperties.class,
    GitHubAuthenticationProperties.class,
    GoogleAuthenticationProperties.class
})
@RequestMapping(path = "/admin/edit-user")
@Slf4j
public class UserProfileEditController extends AbstractUserProfileChangeController {

  private final ValidationProperties validationProperties;

  private final FacebookAuthenticationProperties facebookProperties;

  private final GitHubAuthenticationProperties gitHubProperties;

  private final GoogleAuthenticationProperties googleProperties;

  private final UserProfileService userProfileService;

  private final OAuth2ForeignTokenService foreignTokenService;

  private final RoleService roleService;

  @Autowired
  public UserProfileEditController( // NOSONAR
      final ValidationProperties validationProperties,
      final FacebookAuthenticationProperties facebookProperties,
      final GitHubAuthenticationProperties gitHubProperties,
      final GoogleAuthenticationProperties googleProperties,
      final UserProfileService userProfileService,
      final OAuth2ForeignTokenService foreignTokenService,
      final RoleService roleService,
      final SambaConnectorService sambaConnectorService,
      final LocaleResolver localeResolver) {

    super(sambaConnectorService, localeResolver);
    this.validationProperties = validationProperties;
    this.facebookProperties = facebookProperties;
    this.gitHubProperties = gitHubProperties;
    this.googleProperties = googleProperties;
    this.userProfileService = userProfileService;
    this.foreignTokenService = foreignTokenService;
    this.roleService = roleService;
  }

  @ModelAttribute("gitHubConnected")
  public boolean gitHubConnected(HttpServletRequest request) {
    final String userName = request.getParameter("user");
    return "GET".equalsIgnoreCase(request.getMethod()) && StringUtils.hasText(userName)
        && foreignTokenService.isAccountConnected(userName, gitHubProperties.getProvider());
  }

  @ModelAttribute("googleConnected")
  public boolean googleConnected(HttpServletRequest request) {
    final String userName = request.getParameter("user");
    return "GET".equalsIgnoreCase(request.getMethod()) && StringUtils.hasText(userName)
        && foreignTokenService.isAccountConnected(userName, googleProperties.getProvider());
  }

  @ModelAttribute("facebookConnected")
  public boolean facebookConnected(HttpServletRequest request) {
    final String userName = request.getParameter("user");
    return "GET".equalsIgnoreCase(request.getMethod()) && StringUtils.hasText(userName)
        && foreignTokenService.isAccountConnected(userName, facebookProperties.getProvider());
  }

  @ModelAttribute("mobilePattern")
  public String mobilePattern() {
    return validationProperties.getMobilePattern().pattern();
  }

  @ModelAttribute("locales")
  public List<SelectOptionDto> locales(HttpServletRequest request) {
    return getAvailableLocales(resolveLocale(request));
  }

  @ModelAttribute("zones")
  public List<SelectOptionDto> zones(HttpServletRequest request) {
    return getAvailableTimeZones(resolveLocale(request), resolveTimeZone(request));
  }

  @ModelAttribute("roles")
  public List<SelectOptionDto> roles(HttpServletRequest request) {
    final String userName = request.getParameter("user");
    if (!"GET".equalsIgnoreCase(request.getMethod())
        || !StringUtils.hasText(userName)) {
      return Collections.emptyList();
    }

    final Set<String> defaultRoleNames = new LinkedHashSet<>(
        Arrays.asList(RoleConstants.USER_ROLES));
    final Set<String> grantedRoleNames = roleService.getRoles(userName);
    final List<SelectOptionDto> options = new ArrayList<>();
    for (String role : defaultRoleNames) {
      options.add(new SelectOptionDto(role, role, grantedRoleNames.contains(role)));
    }
    for (String role : grantedRoleNames) {
      if (!defaultRoleNames.contains(role)) {
        options.add(new SelectOptionDto(role, role, true));
      }
    }
    return options;
  }

  @ModelAttribute("sambaGroups")
  public List<SelectOptionDto> sambaGroups(HttpServletRequest request) {

    final String userName = request.getParameter("user");
    if (!"GET".equalsIgnoreCase(request.getMethod())
        || !StringUtils.hasText(userName)) {
      return Collections.emptyList();
    }
    final UserProfileDto userProfile = userProfileService.getUserProfile(userName);
    final boolean hasSambaGroups = userProfile.getSambaSettings() != null;
    final Set<String> sambaGroups;
    if (hasSambaGroups) {
      sambaGroups = userProfile.getSambaSettings()
          .getSambaGroups()
          .stream()
          .map(this::normalizeDistinguishedName)
          .collect(Collectors.toSet());
    } else {
      sambaGroups = new HashSet<>();
    }
    final List<SelectOptionDto> groups = super.sambaGroups();
    if (groups == null) {
      return Collections.emptyList();
    }
    return groups
        .stream()
        .map(option -> new SelectOptionDto(
            option.getValue(),
            option.getDisplayValue(),
            sambaGroups.contains(normalizeDistinguishedName(option.getValue()))))
        .collect(Collectors.toList());
  }

  @GetMapping
  public String displayEditUserView(
      @RequestParam("user") final String userName,
      final ModelMap model) {

    if (!model.containsAttribute("user")) {
      final UserProfileDto userProfile = userProfileService.getUserProfile(userName);
      final UserProfileEditCommand user = new UserProfileEditCommand(
          userProfile,
          roleService.getRoles(userName));
      model.addAttribute("user", user);
    }
    return "admin/edit-user";
  }

  @PostMapping
  public String updateUser(
      @ModelAttribute("user") final UserProfileEditCommand user,
      final ModelMap model,
      final HttpServletRequest request,
      final BindingResult bindingResult,
      final RedirectAttributes redirectAttributes) {

    log.info("Updating user: {}", user);

    try {
      if (!user.isSambaActivated()) {
        user.setSambaSettings(null);
      } else {
        final List<String> decodedGroupList = user.getSambaSettings()
            .getSambaGroups()
            .stream()
            .map(this::urlDecode)
            .collect(Collectors.toList());
        if (log.isDebugEnabled()) {
          log.debug("Decoded samba groups: {}", decodedGroupList);
        }
        user.getSambaSettings().setSambaGroups(decodedGroupList);
      }
      final UserProfileDto dto = userProfileService.updateUserProfile(user.getUserName(), user);

      final Set<String> newRoles = new HashSet<>(user.getRoles());
      newRoles.add(RoleConstants.USER_ROLE);
      roleService.setRoles(dto.getUserName(), newRoles);

      model.clear();
      final String msg = getMessageSource().getMessage(
          "i18n.user.updated",
          new Object[]{dto.getDisplayName()},
          resolveLocale(request));
      final RedirectMessage rmsg = new RedirectMessage(msg, RedirectMessageType.SUCCESS);
      redirectAttributes.addFlashAttribute(RedirectMessage.ATTRIBUTE_NAME, rmsg);
      log.info("User was successfully updated: {}", dto);
      return "redirect:/admin/users";


    } catch (InvalidMobileException e) {
      bindingResult.rejectValue("mobile", "i18n.mobile.invalid");

    } catch (InvalidEmailException e) {
      final String code = StringUtils.hasText(user.getEmail()) ? "i18n.mobile.invalid"
          : "i18n.email.address.required";
      bindingResult.rejectValue("email", code);

    } catch (EmailAlreadyExistsException e) {
      bindingResult.rejectValue("email", "i18n.email.address.already.exists");

    } catch (InvalidLocaleException e) {
      final String code = StringUtils.hasText(user.getPreferredLocale())
          ? "i18n.preferred.locale.invalid" : "i18n.preferred.locale.required";
      bindingResult.rejectValue("preferredLocale", code);

    } catch (InvalidTimeZoneException e) {
      final String code = StringUtils.hasText(user.getPreferredLocale())
          ? "i18n.preferred.time.zone.invalid" : "i18n.preferred.time.zone.required";
      bindingResult.rejectValue("preferredTimeZoneId", code);
    }

    return "admin/edit-user";
  }

}

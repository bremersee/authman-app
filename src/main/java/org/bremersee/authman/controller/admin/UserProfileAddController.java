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

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TimeZone;
import java.util.stream.Collectors;
import javax.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.bremersee.authman.business.RoleService;
import org.bremersee.authman.business.SambaConnectorService;
import org.bremersee.authman.business.UserProfileService;
import org.bremersee.authman.controller.RedirectMessage;
import org.bremersee.authman.controller.RedirectMessageType;
import org.bremersee.authman.exception.EmailAlreadyExistsException;
import org.bremersee.authman.exception.InvalidEmailException;
import org.bremersee.authman.exception.InvalidLocaleException;
import org.bremersee.authman.exception.InvalidTimeZoneException;
import org.bremersee.authman.exception.InvalidUserNameException;
import org.bremersee.authman.exception.PasswordTooWeakException;
import org.bremersee.authman.exception.UserNameAlreadyExistsException;
import org.bremersee.authman.model.SelectOptionDto;
import org.bremersee.authman.model.UserProfileDto;
import org.bremersee.authman.security.core.RoleConstants;
import org.bremersee.authman.validation.ValidationProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.util.StringUtils;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * @author Christian Bremer
 */
@Controller
@RequestMapping(path = "/admin/add-user")
@Slf4j
public class UserProfileAddController extends AbstractUserProfileChangeController {

  private final ValidationProperties validationProperties;

  private final UserProfileService userProfileService;

  private final RoleService roleService;

  @Autowired
  public UserProfileAddController(
      final ValidationProperties validationProperties,
      final UserProfileService userProfileService,
      final RoleService roleService,
      final SambaConnectorService sambaConnectorService,
      final LocaleResolver localeResolver) {
    super(sambaConnectorService, localeResolver);
    this.validationProperties = validationProperties;
    this.userProfileService = userProfileService;
    this.roleService = roleService;
  }

  @ModelAttribute("userNamePattern")
  public String userNamePattern() {
    return validationProperties.getUserNamePattern().pattern();
  }

  @ModelAttribute("passwordPattern")
  public String passwordPattern() {
    return validationProperties.getPasswordPattern().pattern();
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
  public List<SelectOptionDto> roles() {
    return Arrays
        .stream(RoleConstants.USER_ROLES)
        .map(roleName -> new SelectOptionDto(
            roleName,
            roleName,
            RoleConstants.USER_ROLE.equals(roleName)))
        .collect(Collectors.toList());
  }

  @ModelAttribute("sambaGroups")
  public List<SelectOptionDto> sambaGroups() {
    return super.sambaGroups();
  }

  @GetMapping
  public String displayAddUserView(ModelMap model, HttpServletRequest request) {

    if (!model.containsAttribute("user")) {
      final Locale locale = resolveLocale(request);
      final TimeZone timeZone = resolveTimeZone(request);
      final UserProfileAddCommand user = new UserProfileAddCommand(locale, timeZone);
      model.addAttribute("user", user);
    }
    return "admin/add-user";
  }

  @PostMapping
  public String addUser( // NOSONAR
      @ModelAttribute("user") final UserProfileAddCommand user,
      final ModelMap model,
      final HttpServletRequest request,
      final BindingResult bindingResult,
      final RedirectAttributes redirectAttributes) {

    log.info("Adding user: {}", user);

    try {
      if (!user.isSambaActivated()) {
        user.setSambaSettings(null);
      }
      final UserProfileDto dto = userProfileService.createUserProfile(
          user,
          false,
          user.isSendNotification());

      final Set<String> newRoles = new HashSet<>(user.getRoles());
      newRoles.add(RoleConstants.USER_ROLE);
      newRoles.forEach(roleName -> roleService.addRole(dto.getUserName(), roleName));

      model.clear();
      final String msg = getMessageSource().getMessage(
          "i18n.user.created",
          new Object[]{dto.getDisplayName()},
          resolveLocale(request));
      final RedirectMessage rmsg = new RedirectMessage(msg, RedirectMessageType.SUCCESS);
      redirectAttributes.addFlashAttribute(RedirectMessage.ATTRIBUTE_NAME, rmsg);
      log.info("User was successfully created: {}", dto);
      return "redirect:/admin/users";


    } catch (InvalidUserNameException e) {
      final String code = StringUtils.hasText(user.getUserName()) ? "i18n.user.name.invalid"
          : "i18n.user.name.required";
      bindingResult.rejectValue("userName", code);

    } catch (UserNameAlreadyExistsException e) {
      bindingResult.rejectValue("userName", "i18n.user.name.already.exits");

    } catch (InvalidEmailException e) {
      final String code = StringUtils.hasText(user.getEmail()) ? "i18n.email.address.invalid"
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

    } catch (PasswordTooWeakException e) {
      bindingResult.rejectValue("password", "i18n.password.too.weak"); // NOSONAR
    }

    return "admin/add-user";
  }

}

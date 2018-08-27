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

package org.bremersee.authman.controller;

import java.io.Serializable;
import javax.servlet.http.HttpServletRequest;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.bremersee.authman.business.UserProfileService;
import org.bremersee.authman.exception.PasswordTooWeakException;
import org.bremersee.authman.exception.PasswordsNotMatchException;
import org.bremersee.authman.security.core.SecurityHelper;
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
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * @author Christian Bremer
 */
@Controller
@RequestMapping("/password-change")
@Slf4j
public class PasswordChangeController extends AbstractController {

  private ValidationProperties validationProperties;

  private UserProfileService userProfileService;

  @Autowired
  public PasswordChangeController(
      final ValidationProperties validationProperties,
      final UserProfileService userProfileService,
      final LocaleResolver localeResolver) {

    super(localeResolver);
    this.validationProperties = validationProperties;
    this.userProfileService = userProfileService;
  }

  @ModelAttribute("passwordPattern")
  public String passwordPattern() {
    return validationProperties.getPasswordPattern().pattern();
  }

  @GetMapping
  public String displayChangePasswordView(final ModelMap model) {

    final String userName = SecurityHelper.getCurrentUserName();
    final boolean isPasswordPresent = userProfileService.isPasswordPresent(userName);
    log.info("Displaying change password view for user [{}]. User has password? {}",
        userName, isPasswordPresent);

    if (!model.containsAttribute("changePasswordCmd")) {
      model.addAttribute("changePasswordCmd",
          new PasswordChangeCommand(isPasswordPresent));
    }
    return "password-change";
  }

  @PostMapping
  public String changePassword(
      @ModelAttribute("changePasswordCmd") final PasswordChangeCommand passwordChangeCommand,
      @RequestParam(name = "rloc", defaultValue = "/authman") final String redirectLocation,
      final ModelMap model,
      final HttpServletRequest request,
      final BindingResult bindingResult,
      final RedirectAttributes redirectAttributes) {

    final String userName = SecurityHelper.getCurrentUserName();
    log.info("Changing password of user {}.", userName);

    final String newPassword = passwordChangeCommand.getPassword();
    final String newPasswordRepetition = passwordChangeCommand.getPasswordRepetition();

    if (StringUtils.hasText(newPassword)
        && StringUtils.hasText(newPasswordRepetition)
        && !newPassword.equals(newPasswordRepetition)) {

      bindingResult.rejectValue("password", "passwords.new.not.match"); // NOSONAR
      bindingResult.rejectValue("passwordRepetition", "passwords.new.not.match");

    } else {

      try {
        userProfileService.changePassword(
            userName,
            passwordChangeCommand.getCurrentPassword(),
            newPassword);

      } catch (final PasswordsNotMatchException e) {
        bindingResult.rejectValue("currentPassword", "password.current.wrong");

      } catch (final PasswordTooWeakException e) {
        bindingResult.rejectValue("password", "password.new.too.weak"); // NOSONAR
      }
    }

    if (bindingResult.hasErrors()) {
      log.info("Password validation fails. Displaying password change view again ...");
      return "password-change";
    }

    model.clear();
    final String msg = getMessageSource().getMessage(
        "password.change.success",
        new Object[0],
        resolveLocale(request));
    final RedirectMessage rmsg = new RedirectMessage(msg, RedirectMessageType.SUCCESS);
    redirectAttributes.addFlashAttribute(RedirectMessage.ATTRIBUTE_NAME, rmsg);
    log.info("Password of user [{}] was successfully changed.", userName);
    return "redirect:" + redirectLocation;
  }

  @SuppressWarnings("WeakerAccess")
  @Getter
  @Setter
  @NoArgsConstructor
  @RequiredArgsConstructor
  public static class PasswordChangeCommand implements Serializable {

    private static final long serialVersionUID = 90409218782407443L;

    /**
     * Has the user a password?
     */
    @NonNull
    private boolean currentPasswordPresent;

    /**
     * Current password value.
     */
    private String currentPassword;

    /**
     * New password value.
     */
    private String password;

    /**
     * Confirmed password value.
     */
    private String passwordRepetition;
  }
}

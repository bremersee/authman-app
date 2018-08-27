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

import java.io.Serializable;
import javax.servlet.http.HttpServletRequest;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.bremersee.authman.business.UserProfileService;
import org.bremersee.authman.controller.AbstractController;
import org.bremersee.authman.controller.RedirectMessage;
import org.bremersee.authman.controller.RedirectMessageType;
import org.bremersee.authman.exception.PasswordTooWeakException;
import org.bremersee.authman.model.UserProfileDto;
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
@RequestMapping(path = "/admin/change-password")
@Slf4j
public class ChangePasswordController extends AbstractController {

  private final ValidationProperties validationProperties;

  private final UserProfileService userProfileService;

  @Autowired
  public ChangePasswordController(
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
  public String displayChangePasswordView(
      @RequestParam("user") final String userName,
      final ModelMap model) {

    if (!model.containsAttribute("user")) {
      final UserProfileDto userProfile = userProfileService.getUserProfile(userName);
      model.addAttribute("user", userProfile);
    }
    if (!model.containsAttribute("changePasswordCmd")) {
      model.addAttribute("changePasswordCmd", new PasswordResetCommand());
    }
    return "admin/change-password";
  }

  @PostMapping
  public String changePassword(
      @RequestParam("user") String userName,
      @ModelAttribute("changePasswordCmd") final PasswordResetCommand passwordChangeCommand,
      final ModelMap model,
      final HttpServletRequest request,
      final BindingResult bindingResult,
      final RedirectAttributes redirectAttributes) {

    log.info("Changing password of user [{}].", userName);

    final UserProfileDto userProfile;
    try {
      userProfile = userProfileService.resetPassword(
          userName, passwordChangeCommand.getPassword());

    } catch (final PasswordTooWeakException e) {

      bindingResult.rejectValue("password", "password.new.too.weak"); // NOSONAR
      return "admin/change-password";
    }

    model.clear();

    final String name = StringUtils.hasText(userProfile.getDisplayName())
        ? userProfile.getDisplayName() : userName;
    final String msg = getMessageSource().getMessage(
        "i18n.user.password.changed",
        new Object[]{name},
        resolveLocale(request));
    final RedirectMessage rmsg = new RedirectMessage(msg, RedirectMessageType.SUCCESS);
    redirectAttributes.addFlashAttribute(RedirectMessage.ATTRIBUTE_NAME, rmsg);
    log.info("Password of user [{}] was successfully changed.", userName);
    return "redirect:/admin/users";
  }

  @SuppressWarnings("WeakerAccess")
  @Getter
  @Setter
  public static class PasswordResetCommand implements Serializable {

    private static final long serialVersionUID = 90409218782407443L;

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

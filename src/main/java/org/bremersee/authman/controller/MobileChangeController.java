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
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.bremersee.authman.business.MobileChangeService;
import org.bremersee.authman.exception.InvalidMobileException;
import org.bremersee.authman.exception.NotFoundException;
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
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * @author Christian Bremer
 */
@Controller("mobileChangeController")
@Slf4j
public class MobileChangeController extends AbstractController {

  private final ValidationProperties validationProperties;

  private final MobileChangeService mobileChangeService;

  @Autowired
  public MobileChangeController(
      final ValidationProperties validationProperties,
      final MobileChangeService mobileChangeService,
      final LocaleResolver localeResolver) {
    super(localeResolver);
    this.validationProperties = validationProperties;
    this.mobileChangeService = mobileChangeService;
  }

  @GetMapping(path = "/mobile-change")
  public String displayChangeMobileView(final ModelMap model) {

    log.info("Displaying mobile email view for user [{}].", SecurityHelper.getCurrentUserName());

    if (!model.containsAttribute("cmd")) {
      model.addAttribute("cmd", new MobileChangeCommand());
    }
    model.addAttribute("mobilePattern",
        validationProperties.getMobilePattern().pattern());
    return "mobile-change";
  }

  @PostMapping(path = "/mobile-change")
  public String processChangeEmailRequest(
      @ModelAttribute("cmd") final MobileChangeCommand cmd,
      final ModelMap model,
      final BindingResult bindingResult,
      final RedirectAttributes redirectAttributes) {

    try {
      mobileChangeService.saveMobileChangeRequest(
          SecurityHelper.getCurrentUserName(), cmd.getNewMobile());

    } catch (InvalidMobileException e) {
      bindingResult.rejectValue("newMobile", "mobile.change.invalid");
    }

    if (bindingResult.hasErrors()) {
      log.info("Mobile number validation fails. Displaying mobile change view again ...");
      return "mobile-change";
    }

    model.clear();
    redirectAttributes.addFlashAttribute("valid-confirmation-call", "yes");
    return "redirect:/mobile-change-confirmation";
  }

  @GetMapping(path = "/mobile-change-confirmation")
  public String displayMobileChangeConfirmation(
      @ModelAttribute(value = "valid-confirmation-call", binding = false) final String legal,
      ModelMap model) {

    if (!"yes".equals(legal)) {
      throw new NotFoundException();
    }
    if (!model.containsAttribute("cmd")) {
      model.addAttribute("cmd", new MobileConfirmationCommand());
    }
    return "mobile-change-confirmation";
  }

  @PostMapping(path = "/mobile-change-confirmation")
  public String processMobileChangeConfirmation(
      @ModelAttribute("cmd") final MobileConfirmationCommand cmd,
      final ModelMap model,
      final HttpServletRequest request,
      final BindingResult bindingResult,
      final RedirectAttributes redirectAttributes) {

    if (!StringUtils.hasText(cmd.getCode())) {
      bindingResult.rejectValue("code", "mobile.change.code.invalid");

    } else {

      try {
        mobileChangeService.processMobileChangeByHash(cmd.getCode());

      } catch (NotFoundException e) {
        bindingResult.rejectValue("code", "mobile.change.code.invalid");
      }
    }

    if (bindingResult.hasErrors()) {
      return "mobile-change-confirmation";
    }

    model.clear();
    final String msg = getMessageSource().getMessage(
        "mobile.change.success",
        new Object[0],
        resolveLocale(request));
    RedirectMessage rmsg = new RedirectMessage(msg, RedirectMessageType.SUCCESS);
    redirectAttributes.addFlashAttribute(RedirectMessage.ATTRIBUTE_NAME, rmsg);
    return "redirect:/profile";
  }

  @SuppressWarnings("WeakerAccess")
  @Data
  public static class MobileChangeCommand implements Serializable {

    private static final long serialVersionUID = 645984053296607662L;

    private String newMobile;
  }

  @SuppressWarnings("WeakerAccess")
  @Data
  public static class MobileConfirmationCommand implements Serializable {

    private static final long serialVersionUID = 6566328916386051943L;

    private String code;
  }

}

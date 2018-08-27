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
import org.bremersee.authman.business.EmailChangeService;
import org.bremersee.authman.exception.EmailAlreadyExistsException;
import org.bremersee.authman.exception.InvalidEmailException;
import org.bremersee.authman.security.core.SecurityHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
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
@Controller("emailChangeController")
@RequestMapping("/email-change")
@Slf4j
public class EmailChangeController extends AbstractController {

  private final EmailChangeService emailChangeService;

  @Autowired
  public EmailChangeController(
      final EmailChangeService emailChangeService,
      final LocaleResolver localeResolver) {
    super(localeResolver);
    this.emailChangeService = emailChangeService;
  }

  @GetMapping
  public String displayChangeEmailView(final ModelMap model) {

    log.info("Displaying change email view for user [{}].", SecurityHelper.getCurrentUserName());

    if (!model.containsAttribute("cmd")) {
      model.addAttribute("cmd", new EmailChangeCommand());
    }
    return "email-change";
  }

  @PostMapping
  public String processChangeEmailRequest(
      @ModelAttribute("cmd") final EmailChangeCommand cmd,
      final ModelMap model,
      final HttpServletRequest request,
      final BindingResult bindingResult,
      final RedirectAttributes redirectAttributes) {

    try {
      emailChangeService
          .saveEmailChangeRequest(SecurityHelper.getCurrentUserName(), cmd.getNewEmail());

    } catch (InvalidEmailException e) {
      bindingResult.rejectValue("newEmail", "email.change.invalid");

    } catch (EmailAlreadyExistsException e) {
      bindingResult.rejectValue("newEmail", "email.change.exists");
    }

    if (bindingResult.hasErrors()) {
      log.info("Email validation fails. Displaying email change view again ...");
      return "email-change";
    }

    model.clear();
    final String msg = getMessageSource().getMessage(
        "email.change.sent",
        new Object[0],
        resolveLocale(request));
    final RedirectMessage rmsg = new RedirectMessage(msg, RedirectMessageType.INFO);
    redirectAttributes.addFlashAttribute(RedirectMessage.ATTRIBUTE_NAME, rmsg);
    return "redirect:/profile";
  }

  @GetMapping(params = {"hash"})
  public String processChangeEmailConfirmation(
      @RequestParam(name = "hash") String hash,
      final ModelMap model,
      final HttpServletRequest request,
      final RedirectAttributes redirectAttributes) {

    RedirectMessage rmsg;
    try {
      emailChangeService.processEmailChangeByHash(hash);

      final String msg = getMessageSource().getMessage(
          "email.change.success",
          new Object[0],
          resolveLocale(request));
      rmsg = new RedirectMessage(msg, RedirectMessageType.SUCCESS);

    } catch (EmailAlreadyExistsException e) {
      final String msg = getMessageSource().getMessage(
          "email.change.failed.exists",
          new Object[0],
          resolveLocale(request));
      rmsg = new RedirectMessage(msg, RedirectMessageType.DANGER);
    }

    model.clear();
    redirectAttributes.addFlashAttribute(RedirectMessage.ATTRIBUTE_NAME, rmsg);
    return "redirect:/profile";
  }

  @SuppressWarnings("WeakerAccess")
  @Data
  public static class EmailChangeCommand implements Serializable {

    private static final long serialVersionUID = -2554342960234968411L;

    private String newEmail;
  }

}

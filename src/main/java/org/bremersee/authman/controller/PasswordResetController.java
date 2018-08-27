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
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.bremersee.authman.business.PasswordResetService;
import org.bremersee.authman.exception.NoEmailException;
import org.bremersee.authman.exception.NotFoundException;
import org.bremersee.authman.exception.PasswordTooWeakException;
import org.bremersee.authman.validation.ValidationProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.util.StringUtils;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * @author Christian Bremer
 */
@Controller
@Slf4j
public class PasswordResetController extends AbstractController {

  private final ValidationProperties validationProperties;

  private final PasswordResetService passwordResetService;

  @Autowired
  public PasswordResetController(
      final ValidationProperties validationProperties,
      final PasswordResetService passwordResetService,
      final LocaleResolver localeResolver) {

    super(localeResolver);
    this.validationProperties = validationProperties;
    this.passwordResetService = passwordResetService;
  }

  @GetMapping(path = "/password-reset")
  public String displayPasswordResetRequestView(final ModelMap model) {

    if (!model.containsAttribute("cmd")) {
      model.addAttribute("cmd", new PasswordResetRequestCommand());
    }
    return "password-reset-request"; // NOSONAR
  }

  @PostMapping(path = "/password-reset")
  public String processPasswordResetRequest(
      @ModelAttribute("cmd") final PasswordResetRequestCommand cmd,
      final BindingResult bindingResult,
      final RedirectAttributes redirectAttributes) {

    log.info("Processing password reset request {}", cmd);

    if (!StringUtils.hasText(cmd.getUserNameOrEmail())) {
      bindingResult.rejectValue(
          "userNameOrEmail", "user.name.or.email.required"); // NOSONAR
    }
    if (bindingResult.hasErrors()) {
      return "password-reset-request";
    }

    try {
      passwordResetService.savePasswordResetRequest(cmd.getUserNameOrEmail());
      log.info("Password reset request for user [{}] was successfully saved. {}",
          cmd.getUserNameOrEmail(), "Redirecting to /password-reset-enqueued");

    } catch (NotFoundException e) {
      log.debug("Processing password reset request for user {} failed: No user was found.",
          cmd.getUserNameOrEmail());

    } catch (NoEmailException e) {
      bindingResult.rejectValue("userNameOrEmail", "password.reset.no.email");
    }

    if (bindingResult.hasErrors()) {
      return "password-reset-request";
    }

    redirectAttributes.addFlashAttribute("legal-password-request-reset", "yes");
    return "redirect:/password-reset-enqueued";
  }

  @GetMapping(path = "/password-reset-enqueued")
  public String displayPasswordResetRequestView(
      @ModelAttribute(value = "legal-password-request-reset", binding = false) final String legal) {

    if (!"yes".equals(legal)) {
      log.warn("There's no password reset request - redirecting to '/password-reset'");
      return "redirect:/password-reset";
    }
    return "password-reset-enqueued";
  }

  @GetMapping(path = "/password-reset", params = {"hash"})
  public String doPasswordReset(
      @RequestParam(name = "hash") final String hash,
      final ModelMap model) {

    if (!passwordResetService.isResetHashValid(hash)) {
      throw new NotFoundException();
    }
    if (!model.containsAttribute("cmd")) {
      model.addAttribute("cmd", new PasswordResetCommand(hash));
    }
    model.addAttribute("passwordPattern",
        validationProperties.getPasswordPattern().pattern());
    return "password-reset-form"; // NOSONAR
  }

  @PostMapping(path = "/password-reset-form")
  public String doPasswordReset(
      @ModelAttribute("cmd") final PasswordResetCommand cmd,
      final BindingResult bindingResult,
      final RedirectAttributes redirectAttributes) {

    log.info("Processing password reset {}", cmd);

    if (!StringUtils.hasText(cmd.getHash())) {
      throw new NotFoundException();
    }

    if (StringUtils.hasText(cmd.getPassword())
        && !cmd.getPassword().equals(cmd.getPasswordRepetition())) {
      bindingResult.rejectValue("password", "passwords.new.not.match"); // NOSONAR
      bindingResult.rejectValue("passwordRepetition", "passwords.new.not.match");
      return "password-reset-form";
    }

    try {
      passwordResetService.processPasswordResetByHash(cmd.getHash(), cmd.getPassword());

    } catch (PasswordTooWeakException e) {
      bindingResult.rejectValue("password", "password.new.too.weak"); // NOSONAR
      return "password-reset-form";
    }

    redirectAttributes.addFlashAttribute("legal-password-request-success", "yes");
    return "redirect:/password-reset-success";
  }

  @GetMapping(path = "/password-reset-success")
  public String displayPasswordResetSuccess(
      @ModelAttribute(value = "legal-password-request-success", binding = false) final String legal) {

    if (!"yes".equals(legal)) {
      log.warn("There's no password reset request - redirecting to '/password-reset'");
      return "redirect:/password-reset";
    }

    return "password-reset-success";
  }

  @SuppressWarnings("WeakerAccess")
  @Data
  @NoArgsConstructor
  public static class PasswordResetRequestCommand implements Serializable {

    private static final long serialVersionUID = -5531054468122323108L;

    private String userNameOrEmail;
  }

  @SuppressWarnings("WeakerAccess")
  @Getter
  @Setter
  @ToString(of = {"hash"})
  @EqualsAndHashCode
  @NoArgsConstructor
  public static class PasswordResetCommand implements Serializable {

    private static final long serialVersionUID = 4901462726269300603L;

    private String hash;

    private String password;

    private String passwordRepetition;

    /**
     * Constructs a new password reset command with the specified reset hash.
     *
     * @param hash the reset hash
     */
    public PasswordResetCommand(final String hash) {
      this.hash = hash;
    }
  }
}

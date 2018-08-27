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

import java.util.List;
import java.util.Locale;
import java.util.TimeZone;
import javax.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.bremersee.authman.business.RegistrationService;
import org.bremersee.authman.exception.EmailAlreadyExistsException;
import org.bremersee.authman.exception.InvalidEmailException;
import org.bremersee.authman.exception.InvalidLocaleException;
import org.bremersee.authman.exception.InvalidTimeZoneException;
import org.bremersee.authman.exception.InvalidUserNameException;
import org.bremersee.authman.exception.PasswordTooWeakException;
import org.bremersee.authman.exception.UserNameAlreadyExistsException;
import org.bremersee.authman.model.SelectOptionDto;
import org.bremersee.authman.model.UserProfileCreateRequestDto;
import org.bremersee.authman.model.UserProfileDto;
import org.bremersee.authman.validation.ValidationProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.util.StringUtils;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * @author Christian Bremer
 */
@Controller("userRegistrationController")
@RequestMapping("/register")
@EnableConfigurationProperties(ValidationProperties.class)
@Slf4j
public class UserRegistrationController extends AbstractController {

  private final ValidationProperties validationProperties;

  private final RegistrationService registrationService;

  @Autowired
  public UserRegistrationController(
      final ValidationProperties validationProperties,
      final RegistrationService registrationService,
      final LocaleResolver localeResolver) {

    super(localeResolver);
    this.validationProperties = validationProperties;
    this.registrationService = registrationService;
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

  @RequestMapping(
      method = RequestMethod.GET)
  public String displayRegistrationView(ModelMap model, HttpServletRequest request) {

    if (!model.containsAttribute("registration")) {
      final Locale locale = resolveLocale(request);
      final TimeZone timeZone = resolveTimeZone(request);
      UserProfileCreateRequestDto registration = new UserProfileCreateRequestDto();
      registration.setPreferredLocale(locale.toString());
      registration.setPreferredTimeZoneId(timeZone.getID());
      model.addAttribute("registration", registration);
    }
    return "register";
  }

  @RequestMapping(
      method = RequestMethod.POST)
  public String doRegistration(
      @ModelAttribute("registration") UserProfileCreateRequestDto registration,
      ModelMap model,
      BindingResult bindingResult,
      RedirectAttributes redirectAttributes) {

    log.info("Registering {}", registration);

    try {
      registrationService.saveRegistrationRequest(registration);

    } catch (EmailAlreadyExistsException e) {
      logRegistrationException(registration, e);
      bindingResult.rejectValue("email", "i18n.email.address.already.exists");

    } catch (InvalidEmailException e) {
      logRegistrationException(registration, e);
      final String code = StringUtils.hasText(registration.getEmail())
          ? "i18n.email.address.invalid" : "i18n.email.address.required";
      bindingResult.rejectValue("email", code);

    } catch (InvalidLocaleException e) {
      logRegistrationException(registration, e);
      final String code = StringUtils.hasText(registration.getPreferredLocale())
          ? "i18n.preferred.locale.invalid" : "i18n.preferred.locale.required";
      bindingResult.rejectValue("preferredLocale", code);

    } catch (InvalidTimeZoneException e) {
      logRegistrationException(registration, e);
      final String code = StringUtils.hasText(registration.getPreferredLocale())
          ? "i18n.preferred.time.zone.invalid" : "i18n.preferred.time.zone.required";
      bindingResult.rejectValue("preferredTimeZoneId", code);

    } catch (InvalidUserNameException e) {
      logRegistrationException(registration, e);
      final String code = StringUtils.hasText(registration.getUserName())
          ? "i18n.user.name.invalid" : "i18n.user.name.required";
      bindingResult.rejectValue("userName", code);

    } catch (PasswordTooWeakException e) {
      logRegistrationException(registration, e);
      bindingResult.rejectValue("password", "i18n.password.too.weak"); // NOSONAR

    } catch (UserNameAlreadyExistsException e) {
      logRegistrationException(registration, e);
      bindingResult.rejectValue("userName", "i18n.user.name.already.exits");
    }

    if (bindingResult.hasErrors()) {
      return "register";
    }

    model.clear();
    redirectAttributes.addFlashAttribute("registered", registration);

    log.info("Registration was successfully persisted, email was sent. Redirecting to /registered");
    return "redirect:/registered";
  }

  private void logRegistrationException(final UserProfileCreateRequestDto r, final Exception e) {
    log.info("Registration {} failed: {}", r, e.getMessage());
  }

  @RequestMapping(
      params = {"hash"},
      method = RequestMethod.GET)
  public String doRegistrationValidation(
      @RequestParam(name = "hash") String hash,
      ModelMap model,
      RedirectAttributes redirectAttributes) {

    final UserProfileDto userProfile = registrationService.processUserRegistrationByHash(hash);
    model.clear();

    // TODO redirect to the profile page

    redirectAttributes.addFlashAttribute("userProfile", userProfile);
    log.info("Registration was successfully persisted, email was sent. Redirecting to /registered");
    return "redirect:/login";
  }

}

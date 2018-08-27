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
import javax.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.bremersee.authman.business.OAuth2ForeignTokenService;
import org.bremersee.authman.business.UserProfileService;
import org.bremersee.authman.exception.InvalidLocaleException;
import org.bremersee.authman.exception.InvalidTimeZoneException;
import org.bremersee.authman.model.SelectOptionDto;
import org.bremersee.authman.model.UserProfileDto;
import org.bremersee.authman.security.authentication.facebook.FacebookAuthenticationProperties;
import org.bremersee.authman.security.authentication.github.GitHubAuthenticationProperties;
import org.bremersee.authman.security.authentication.google.GoogleAuthenticationProperties;
import org.bremersee.authman.security.core.SecurityHelper;
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
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * @author Christian Bremer
 */
@Controller("userProfileController")
@RequestMapping("/profile")
@EnableConfigurationProperties({
    FacebookAuthenticationProperties.class,
    GitHubAuthenticationProperties.class,
    GoogleAuthenticationProperties.class
})
@Slf4j
public class UserProfileController extends AbstractController {

  private final ValidationProperties validationProperties;

  private final FacebookAuthenticationProperties facebookProperties;

  private final GitHubAuthenticationProperties gitHubProperties;

  private final GoogleAuthenticationProperties googleProperties;

  private final UserProfileService userService;

  private final OAuth2ForeignTokenService foreignTokenService;

  @Autowired
  public UserProfileController(
      final ValidationProperties validationProperties,
      final FacebookAuthenticationProperties facebookProperties,
      final GitHubAuthenticationProperties gitHubProperties,
      final GoogleAuthenticationProperties googleProperties,
      final UserProfileService userService,
      final OAuth2ForeignTokenService foreignTokenService,
      final LocaleResolver localeResolver) {

    super(localeResolver);
    this.validationProperties = validationProperties;
    this.facebookProperties = facebookProperties;
    this.gitHubProperties = gitHubProperties;
    this.googleProperties = googleProperties;
    this.userService = userService;
    this.foreignTokenService = foreignTokenService;
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

  @ModelAttribute("currentUrl")
  public String currentUrl(HttpServletRequest request) {
    StringBuffer requestURL = request.getRequestURL();
    String queryString = request.getQueryString();

    if (queryString == null) {
      return requestURL.toString();
    } else {
      return requestURL.append('?').append(queryString).toString();
    }
  }

  @ModelAttribute("gitHubConnected")
  public boolean gitHubConnected() {
    return foreignTokenService.isAccountConnected(
        SecurityHelper.getCurrentUserName(), gitHubProperties.getProvider());
  }

  @ModelAttribute("googleConnected")
  public boolean googleConnected() {
    return foreignTokenService.isAccountConnected(
        SecurityHelper.getCurrentUserName(), googleProperties.getProvider());
  }

  @ModelAttribute("facebookConnected")
  public boolean facebookConnected() {
    return foreignTokenService.isAccountConnected(
        SecurityHelper.getCurrentUserName(), facebookProperties.getProvider());
  }

  @GetMapping
  public String displayUserProfileView(ModelMap model) {

    final String userName = SecurityHelper.getCurrentUserName();
    log.info("Displaying user profile of user [{}].", userName);
    if (!model.containsAttribute("profile")) {
      final UserProfileDto userProfile = userService.getUserProfile(userName);
      model.addAttribute("profile", userProfile);
    }
    return "profile";
  }

  @PostMapping
  public String updateProfile(
      @ModelAttribute(name = "profile") UserProfileDto profile,
      final ModelMap model,
      final HttpServletRequest request,
      final BindingResult bindingResult,
      final RedirectAttributes redirectAttributes) {

    final String userName = SecurityHelper.getCurrentUserName();
    try {
      userService.updateUserProfile(userName, profile);

    } catch (InvalidLocaleException e) {
      final String code = StringUtils.hasText(profile.getPreferredLocale())
          ? "i18n.preferred.locale.invalid" : "i18n.preferred.locale.required";
      bindingResult.rejectValue("preferredLocale", code);

    } catch (InvalidTimeZoneException e) {
      final String code = StringUtils.hasText(profile.getPreferredLocale())
          ? "i18n.preferred.time.zone.invalid" : "i18n.preferred.time.zone.required";
      bindingResult.rejectValue("preferredTimeZoneId", code);

    }

    if (bindingResult.hasErrors()) {
      return "profile";
    }

    model.clear();
    final String msg = getMessageSource().getMessage(
        "user.profile.update.success",
        new Object[0],
        resolveLocale(request));
    RedirectMessage rmsg = new RedirectMessage(msg, RedirectMessageType.INFO);
    redirectAttributes.addFlashAttribute(RedirectMessage.ATTRIBUTE_NAME, rmsg);
    return "redirect:/profile";
  }

}

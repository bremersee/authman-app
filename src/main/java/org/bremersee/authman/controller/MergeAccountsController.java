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

import javax.servlet.http.HttpServletRequest;
import javax.validation.constraints.NotNull;
import lombok.extern.slf4j.Slf4j;
import org.bremersee.authman.security.authentication.OAuth2AuthenticationToken;
import org.bremersee.authman.validation.ValidationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.LocaleResolver;

/**
 * @author Christian Bremer
 */
@Controller("mergeAccountsController")
@EnableConfigurationProperties(ValidationProperties.class)
@Slf4j
public class MergeAccountsController extends AbstractController {

  private final ValidationProperties validationProperties;

  public MergeAccountsController(
      @NotNull final LocaleResolver localeResolver,
      @NotNull final ValidationProperties validationProperties) {

    super(localeResolver);
    this.validationProperties = validationProperties;
  }

  @RequestMapping(
      path = "/merge",
      method = RequestMethod.GET)
  public String displayMergeView(
      //@RequestParam(name = "error", required = false) String error,
      final Model model,
      final HttpServletRequest request) {

    log.debug("Displaying merge view.");

    OAuth2AuthenticationToken authToken = OAuth2AuthenticationToken.loadFromSession(request);
    if (authToken == null) {
      log.debug("OAuth2 authentication token not found. Redirecting to login view.");
      return "redirect:/login";
    }

    model.addAttribute("provider", authToken.getProvider());
    model.addAttribute("profile", authToken.getPrincipal());
    model.addAttribute("userNamePattern",
        validationProperties.getUserNamePattern().pattern());

    return "merge";
  }

}

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

package org.bremersee.authman.controller.developer;

import javax.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.bremersee.authman.business.OAuth2ScopeService;
import org.bremersee.authman.controller.AbstractController;
import org.bremersee.authman.controller.RedirectMessage;
import org.bremersee.authman.controller.RedirectMessageType;
import org.bremersee.authman.model.OAuth2ScopeDto;
import org.bremersee.authman.security.core.SecurityHelper;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * @author Christian Bremer
 */
@Controller
@Slf4j
public class OAuth2ScopesController extends AbstractController {

  private final OAuth2ScopeService scopeService;

  public OAuth2ScopesController(
      final OAuth2ScopeService scopeService,
      final LocaleResolver localeResolver) {
    super(localeResolver);
    this.scopeService = scopeService;
  }

  @GetMapping(path = "/developer/scopes")
  public String displayScopes(
      @RequestParam(name = "q", required = false) final String search,
      final Pageable pageable,
      final ModelMap model,
      final HttpServletRequest request) {

    log.info("Displaying scopes with search = {} and pageable = {}", search, pageable);

    if (!model.containsAttribute("scopePage")) {
      final Page<OAuth2ScopeDto> scopePage = scopeService.getScopes(
          search, pageable, resolveLocale(request));
      model.addAttribute("scopePage", scopePage);
    }

    return "developer/scopes";
  }

  @PostMapping(path = "/developer/scopes", params = {"id"})
  public String deleteScope(
      @RequestParam("id") String id,
      ModelMap model,
      HttpServletRequest request,
      RedirectAttributes redirectAttributes) {

    final boolean success = scopeService.deleteScopeById(id);

    model.clear();

    final String msg;
    if (success) {
      msg = getMessageSource().getMessage(
          "oauth2.scope.deleted",
          new Object[0],
          resolveLocale(request));
      log.info("User [{}] has successfully deleted scope with id [{}].",
          SecurityHelper.getCurrentUserName(), id);

    } else {
      msg = getMessageSource().getMessage(
          "oauth2.scope.not.deleted",
          new Object[0],
          resolveLocale(request));
      log.info("User [{}] can not delete scope with id [{}], "
              + "because thar are OAuth2 Clients that depend on it",
          SecurityHelper.getCurrentUserName(), id);

    }

    final RedirectMessage rmsg = new RedirectMessage(msg, RedirectMessageType.SUCCESS);
    redirectAttributes.addFlashAttribute(RedirectMessage.ATTRIBUTE_NAME, rmsg);
    return "redirect:/developer/scopes";
  }
}

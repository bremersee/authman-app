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

import java.util.List;
import javax.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.bremersee.authman.business.OAuth2ScopeService;
import org.bremersee.authman.controller.RedirectMessage;
import org.bremersee.authman.controller.RedirectMessageType;
import org.bremersee.authman.exception.AlreadyExistsException;
import org.bremersee.authman.exception.DescriptionRequiredException;
import org.bremersee.authman.exception.InvalidLanguageException;
import org.bremersee.authman.exception.InvalidScopeNameException;
import org.bremersee.authman.model.OAuth2ScopeDto;
import org.bremersee.authman.model.SelectOptionDto;
import org.bremersee.authman.security.core.SecurityHelper;
import org.bremersee.authman.validation.ValidationProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
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
@RequestMapping(path = "/developer/add-scope")
@Slf4j
public class OAuth2ScopeAddController extends AbstractOAuth2ScopeController {

  @Autowired
  public OAuth2ScopeAddController(
      final ValidationProperties validationProperties,
      final OAuth2ScopeService scopeService,
      final LocaleResolver localeResolver) {
    super(validationProperties, scopeService, localeResolver);
  }

  @ModelAttribute("preferredLanguage")
  public String preferredLanguage(final HttpServletRequest request) {
    return resolveLocale(request).getLanguage();
  }

  @ModelAttribute("visibilities")
  @Override
  public List<SelectOptionDto> visibilities() {
    return super.visibilities();
  }

  @ModelAttribute("languages")
  @Override
  public List<SelectOptionDto> languages(final HttpServletRequest request) {
    return super.languages(request);
  }

  @ModelAttribute("scopeNamePattern")
  public String scopeNamePattern() {
    return getValidationProperties().getScopeNamePattern().pattern();
  }

  @ModelAttribute("scopeDescriptionPattern")
  public String scopeDescriptionPattern() {
    return getValidationProperties().getScopeDescriptionPattern().pattern();
  }

  @GetMapping
  public String displayAddScopeView(
      final ModelMap model,
      final HttpServletRequest request) {

    if (!model.containsAttribute("scope")) { // NOSONAR
      model.addAttribute("scope", newOAuth2ScopeCommand(resolveLocale(request)));
    }
    return "developer/add-scope";
  }

  @PostMapping
  public String addScope(
      @ModelAttribute("scope") final OAuth2ScopeCommand scope,
      final ModelMap model,
      final HttpServletRequest request,
      final BindingResult bindingResult,
      final RedirectAttributes redirectAttributes) {

    log.info("User [{}] adds OAuth2 Scope {}", SecurityHelper.getCurrentUserName(), scope);

    setAdditionalDescriptions(scope, request);
    final OAuth2ScopeDto dto = new OAuth2ScopeDto();
    mapToDto(scope, dto, true);

    try {
      getScopeService().createScope(dto);

    } catch (AlreadyExistsException e) {
      bindingResult.rejectValue("scope", "oauth2.scope.already.exists");

    } catch (InvalidScopeNameException e) {
      bindingResult.rejectValue("scope", "oauth2.scope.name.invalid");

    } catch (InvalidLanguageException e) {
      bindingResult.rejectValue("defaultLanguage", "oauth2.scope.language.invalid");

    } catch (DescriptionRequiredException e) {
      bindingResult.rejectValue("defaultDescription", "oauth2.scope.description.invalid");

    }

    if (bindingResult.hasErrors()) {
      return "developer/add-scope";
    }

    model.clear();
    final String msg = getMessageSource().getMessage(
        "oauth2.scope.created",
        new Object[]{dto.getScope()},
        resolveLocale(request));
    final RedirectMessage rmsg = new RedirectMessage(msg, RedirectMessageType.SUCCESS);
    redirectAttributes.addFlashAttribute(RedirectMessage.ATTRIBUTE_NAME, rmsg);
    log.info("User [{}] has successfully created {}", SecurityHelper.getCurrentUserName(), dto);
    return "redirect:/developer/scopes";
  }
}

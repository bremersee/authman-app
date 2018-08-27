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
import org.bremersee.authman.AuthorizationServerProperties;
import org.bremersee.authman.business.OAuth2ClientService;
import org.bremersee.authman.business.OAuth2ScopeService;
import org.bremersee.authman.controller.RedirectMessage;
import org.bremersee.authman.controller.RedirectMessageType;
import org.bremersee.authman.exception.AuthorizedGrantTypeRequiredException;
import org.bremersee.authman.exception.InvalidClientDisplayNameException;
import org.bremersee.authman.exception.RegisteredRedirectUriRequiredException;
import org.bremersee.authman.exception.ScopeRequiredException;
import org.bremersee.authman.model.OAuth2ClientDto;
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
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * @author Christian Bremer
 */
@Controller
@RequestMapping("/developer/edit-client")
@Slf4j
public class OAuth2ClientEditController extends AbstractOAuth2ClientController {

  @Autowired
  public OAuth2ClientEditController(
      final OAuth2ClientService clientService,
      final ValidationProperties validationProperties,
      final AuthorizationServerProperties authorizationServerProperties,
      final OAuth2ScopeService scopeService,
      final LocaleResolver localeResolver) {
    super(
        validationProperties,
        authorizationServerProperties,
        scopeService,
        clientService,
        localeResolver);
  }

  @ModelAttribute("clientNamePattern")
  public String clientNamePattern() {
    return getValidationProperties().getClientNamePattern().pattern();
  }

  @ModelAttribute("chronoUnits")
  @Override
  public List<SelectOptionDto> chronoUnits(HttpServletRequest request) {
    return super.chronoUnits(request);
  }

  @ModelAttribute("availableScopes")
  @Override
  public List<SelectOptionDto> availableScopes(HttpServletRequest request) {
    return super.availableScopes(request);
  }

  @ModelAttribute("grantTypes")
  @Override
  public List<SelectOptionDto> grantTypes(HttpServletRequest request) {
    return super.grantTypes(request);
  }

  @GetMapping
  public String displayEditClient(
      final @RequestParam("id") String clientId,
      final ModelMap model) {

    log.info("Displaying edit client [{}].", clientId);

    if (!model.containsAttribute("client")) {
      final OAuth2ClientDto dto = getClientService().getClient(clientId);
      model.addAttribute("client", mapToCommand(dto));
    }

    return "developer/edit-client"; // NOSONAR
  }

  @PostMapping
  public String updateClient(
      @ModelAttribute("client") OAuth2ClientCommand client,
      ModelMap model,
      HttpServletRequest request,
      BindingResult bindingResult,
      RedirectAttributes redirectAttributes) {

    log.info("User [{}] edits OAuth2 Client {}", SecurityHelper.getCurrentUserName(), client);

    if (client == null || client.getClientId() == null) {
      bindingResult.rejectValue("clientId", "oauth2.client.id.invalid");
      return "developer/edit-client";
    }

    final boolean isAdmin = SecurityHelper.isCurrentUserAdmin();

    client.getAuthorizedGrantTypes().removeIf(s -> s == null || s.trim().length() == 0);
    client.getAutoApproveScopes().removeIf(s -> s == null || s.trim().length() == 0);
    client.getRegisteredRedirectUri().removeIf(s -> s == null || s.trim().length() == 0);
    client.getScope().removeIf(s -> s == null || s.trim().length() == 0);

    client.getAuthorizedGrantTypes().removeIf(
        s -> !AuthorizationServerProperties.getAuthorizationGrantTypes().keySet().contains(s));

    if (!isAdmin) {
      client.getAuthorizedGrantTypes().removeIf(
          s -> !getAuthorizationServerProperties()
              .getDevelopersAuthorizationGrantTypes().contains(s));
    }

    OAuth2ClientDto dto = getClientService().getClient(client.getClientId());
    try {
      mapToDto(client, dto, false);
      dto = getClientService().updateClient(client.getClientId(), dto);

    } catch (RegisteredRedirectUriRequiredException e) {
      bindingResult.rejectValue("registeredRedirectUri",
          "oauth2.client.redirect.uris.required");

    } catch (AuthorizedGrantTypeRequiredException e) {
      bindingResult.rejectValue("authorizedGrantTypes", "oauth2.client.grants.required");

    } catch (ScopeRequiredException e) {
      bindingResult.rejectValue("scope", "oauth2.client.scope.required");

    } catch (InvalidClientDisplayNameException e) {
      bindingResult.rejectValue("displayName", "oauth2.client.display.name.invalid");
    }

    if (bindingResult.hasErrors()) {
      return "developer/edit-client";
    }

    model.clear();
    final String msg = getMessageSource().getMessage(
        "oauth2.client.updated",
        new Object[]{dto.getDisplayName()},
        resolveLocale(request));
    final RedirectMessage rmsg = new RedirectMessage(msg, RedirectMessageType.SUCCESS);
    redirectAttributes.addFlashAttribute(RedirectMessage.ATTRIBUTE_NAME, rmsg);
    log.info("User [{}] has successfully updated {}", SecurityHelper.getCurrentUserName(), dto);
    return "redirect:/developer/clients";
  }

}

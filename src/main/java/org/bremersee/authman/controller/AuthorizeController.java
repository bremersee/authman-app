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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.validation.constraints.NotNull;
import lombok.extern.slf4j.Slf4j;
import org.bremersee.authman.domain.OAuth2Client;
import org.bremersee.authman.domain.OAuth2ClientRepository;
import org.bremersee.authman.domain.OAuth2Scope;
import org.bremersee.authman.domain.OAuth2ScopeRepository;
import org.bremersee.authman.model.ApprovableOAuth2ScopeDto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.servlet.LocaleResolver;

/**
 * @author Christian Bremer
 */
@Controller("authorizeController")
@SessionAttributes("authorizationRequest")
@Slf4j
public class AuthorizeController extends AbstractController {

  private final OAuth2ClientRepository oauth2ClientRepository;

  private final OAuth2ScopeRepository oauth2ScopeRepository;

  @Autowired
  public AuthorizeController(
      @NotNull final LocaleResolver localeResolver,
      @NotNull final OAuth2ClientRepository oauth2ClientRepository,
      @NotNull final OAuth2ScopeRepository oauth2ScopeRepository) {

    super(localeResolver);
    this.oauth2ClientRepository = oauth2ClientRepository;
    this.oauth2ScopeRepository = oauth2ScopeRepository;
  }

  @RequestMapping(
      path = "/oauth/confirm_access",
      method = RequestMethod.GET)
  public String displayAuthorizeView(Model model, HttpServletRequest request) {

    final Locale locale = resolveLocale(request);

    final AuthorizationRequest authorizationRequest = getAuthorizationRequest(request);
    final String clientId = authorizationRequest.getClientId();

    if (!model.containsAttribute("clientDisplayName")) {
      model.addAttribute("clientDisplayName", getClientDisplayName(clientId));
    }

    if (!model.containsAttribute("approvableScopes")) {
      final Map<String, Boolean> scopes = getScopes(model, request);
      final List<ApprovableOAuth2ScopeDto> approvableScopes = getApprovableScopes(scopes, locale);
      model.addAttribute("approvableScopes", approvableScopes);
    }

    return "authorize";
  }

  private AuthorizationRequest getAuthorizationRequest(HttpServletRequest request) {
    return (AuthorizationRequest) request.getSession().getAttribute("authorizationRequest");
  }

  private String getClientDisplayName(String clientId) {
    final String displayName = oauth2ClientRepository
        .findByClientId(clientId).orElse(new OAuth2Client())
        .getDisplayName();
    return StringUtils.hasText(displayName) ? displayName : clientId;
  }

  private Map<String, Boolean> getScopes(Model model, HttpServletRequest request) {
    return getScopes(model.asMap(), request);
  }

  @SuppressWarnings("unchecked")
  private Map<String, Boolean> getScopes(Map<String, Object> model, HttpServletRequest request) {

    final String name = "scopes";
    log.debug("Looking for scopes ...");
    final Map<String, Object> map;
    if (model.containsKey(name)) {
      map = (Map<String, Object>) model.get(name);
      log.debug("... found scopes in model: {}", map);
    } else {
      map = (Map<String, Object>) request.getAttribute(name);
      log.debug("... found scopes in request attributes: {}", map);
    }

    final Map<String, Boolean> scopes = new HashMap<>();
    for (Map.Entry<String, Object> entry : map.entrySet()) {
      final String entryKey = entry.getKey();
      final String keyWithoutPrefix;
      if (entryKey.startsWith(OAuth2Utils.SCOPE_PREFIX)) {
        keyWithoutPrefix = entryKey.substring(OAuth2Utils.SCOPE_PREFIX.length());
      } else {
        keyWithoutPrefix = entryKey;
      }
      final Object tmp = entry.getValue();
      Boolean value;
      try {
        value = Boolean.valueOf(String.valueOf(tmp));
      } catch (Exception e) {
        value = Boolean.FALSE;
      }
      scopes.put(keyWithoutPrefix, value);
    }

    log.debug("Returning scopes: {}", scopes);
    return scopes;
  }

  private List<ApprovableOAuth2ScopeDto> getApprovableScopes(
      final Map<String, Boolean> scopes,
      final Locale locale) {

    final List<OAuth2Scope> scopeList = oauth2ScopeRepository
        .findByScopeIn(new ArrayList<>(scopes.keySet()));
    final List<ApprovableOAuth2ScopeDto> approvableScopes = new ArrayList<>(scopes.size());
    for (final OAuth2Scope scope : scopeList) {
      ApprovableOAuth2ScopeDto dto = new ApprovableOAuth2ScopeDto();
      dto.setApproved(scopes.get(scope.getScope()));
      dto.setDescription(scope.getDescriptions().get(locale.getLanguage()));
      if (!StringUtils.hasText(dto.getDescription())) {
        dto.setDescription(scope.getDescriptions().get(scope.getDefaultLanguage()));
      }
      dto.setScope(scope.getScope());
      approvableScopes.add(dto);
    }
    return approvableScopes;
  }

}

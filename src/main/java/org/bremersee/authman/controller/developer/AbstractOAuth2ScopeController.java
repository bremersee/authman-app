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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.validation.constraints.NotNull;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.bremersee.authman.business.OAuth2ScopeService;
import org.bremersee.authman.controller.AbstractController;
import org.bremersee.authman.model.OAuth2ScopeDto;
import org.bremersee.authman.model.OAuth2ScopeVisibility;
import org.bremersee.authman.model.SelectOptionDto;
import org.bremersee.authman.security.core.SecurityHelper;
import org.bremersee.authman.validation.ValidationProperties;
import org.springframework.util.StringUtils;
import org.springframework.web.servlet.LocaleResolver;

/**
 * @author Christian Bremer
 */
public abstract class AbstractOAuth2ScopeController extends AbstractController {

  @Getter(AccessLevel.PACKAGE)
  private final ValidationProperties validationProperties;

  @Getter(AccessLevel.PACKAGE)
  private final OAuth2ScopeService scopeService;

  public AbstractOAuth2ScopeController(
      @NotNull final ValidationProperties validationProperties,
      @NotNull final OAuth2ScopeService scopeService,
      @NotNull final LocaleResolver localeResolver) {
    super(localeResolver);
    this.validationProperties = validationProperties;
    this.scopeService = scopeService;
  }

  List<SelectOptionDto> visibilities() {
    final List<SelectOptionDto> list = new ArrayList<>(3);
    list.add(new SelectOptionDto(
        OAuth2ScopeVisibility.PUBLIC.name(),
        OAuth2ScopeVisibility.PUBLIC.name(),
        false));
    list.add(new SelectOptionDto(
        OAuth2ScopeVisibility.PRIVATE.name(),
        OAuth2ScopeVisibility.PRIVATE.name(),
        false));
    if (SecurityHelper.isCurrentUserAdmin()) {
      list.add(new SelectOptionDto(
          OAuth2ScopeVisibility.ADMIN.name(),
          OAuth2ScopeVisibility.ADMIN.name(),
          false));
    }
    return list;
  }

  List<SelectOptionDto> languages(HttpServletRequest request) {
    return getAvailableLanguages(resolveLocale(request));
  }

  void mapToCommand(
      @NotNull final OAuth2ScopeDto source,
      @NotNull final OAuth2ScopeCommand destination) {

    final String currentUser = SecurityHelper.getCurrentUserName();
    final String creator = source.getCreatedBy() == null ? "" : source.getCreatedBy();
    destination.setEditable(SecurityHelper.isCurrentUserAdmin() || creator.equals(currentUser));
    destination.setScope(source.getScope());
    destination.setVisibility(source.getVisibility());
    destination.setDefaultLanguage(source.getDefaultLanguage());
    destination.setDefaultDescription(source.getDescriptions().get(source.getDefaultLanguage()));
    for (Map.Entry<String, String> entry : source.getDescriptions().entrySet()) {
      if (!entry.getKey().equals(source.getDefaultLanguage())) {
        destination.getDescriptions().add(
            new OAuth2ScopeDescription(entry.getKey(), entry.getValue()));
      }
    }
  }

  void mapToDto(
      @NotNull final OAuth2ScopeCommand source,
      @NotNull final OAuth2ScopeDto destination,
      final boolean forCreation) {

    if (forCreation) {
      destination.setScope(source.getScope());
    }
    destination.setVisibility(source.getVisibility());
    destination.setDefaultLanguage(source.getDefaultLanguage());
    destination.setDescription(source.getDefaultDescription());
    destination.getDescriptions().clear();
    for (final OAuth2ScopeDescription description : source.getDescriptions()) {
      if (StringUtils.hasText(description.getLanguage())
          && StringUtils.hasText(description.getDescription())) {
        destination.getDescriptions().put(description.getLanguage(), description.getDescription());
      }
    }
  }

  void setAdditionalDescriptions(
      @NotNull final OAuth2ScopeCommand scope,
      @NotNull final HttpServletRequest request) {

    scope.getDescriptions().clear();
    final Enumeration<String> paramNames = request.getParameterNames();
    while (paramNames.hasMoreElements()) {
      final String paramName = paramNames.nextElement();
      if (paramName.startsWith("language-")) {
        final String no = paramName.substring("language-".length());
        final String description = request.getParameter("description-" + no);
        final String language = request.getParameter(paramName);
        if (StringUtils.hasText(description) && StringUtils.hasText(language)) {
          scope.getDescriptions().add(new OAuth2ScopeDescription(language, description));
        }
      }
    }
  }

  OAuth2ScopeCommand newOAuth2ScopeCommand(final Locale locale) {
    final String lang = locale == null ? Locale.getDefault().getLanguage() : locale.getLanguage();
    final OAuth2ScopeCommand cmd = new OAuth2ScopeCommand();
    cmd.setDefaultLanguage(lang);
    if (!"en".equals(lang)) {
      cmd.getDescriptions().add(new OAuth2ScopeDescription("en", ""));
    }
    return cmd;
  }

  @Data
  @NoArgsConstructor
  public static class OAuth2ScopeCommand implements Serializable {

    private static final long serialVersionUID = 3080634898377449520L;

    private String scope;

    private OAuth2ScopeVisibility visibility = OAuth2ScopeVisibility.PUBLIC;

    private String defaultLanguage;

    private String defaultDescription;

    private List<OAuth2ScopeDescription> descriptions = new ArrayList<>();

    private boolean editable = true;
  }

  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  public static class OAuth2ScopeDescription implements Serializable {

    private static final long serialVersionUID = 7778345342162826155L;

    private String language;

    private String description;
  }
}

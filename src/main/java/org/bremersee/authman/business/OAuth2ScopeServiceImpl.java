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

package org.bremersee.authman.business;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;
import javax.validation.constraints.NotNull;
import lombok.extern.slf4j.Slf4j;
import org.bremersee.authman.domain.OAuth2ClientRepository;
import org.bremersee.authman.domain.OAuth2Scope;
import org.bremersee.authman.domain.OAuth2ScopeRepository;
import org.bremersee.authman.exception.AlreadyExistsException;
import org.bremersee.authman.exception.DescriptionRequiredException;
import org.bremersee.authman.exception.ForbiddenException;
import org.bremersee.authman.exception.InvalidLanguageException;
import org.bremersee.authman.exception.InvalidScopeNameException;
import org.bremersee.authman.exception.NotFoundException;
import org.bremersee.authman.mapper.OAuth2ScopeMapper;
import org.bremersee.authman.model.OAuth2ScopeDto;
import org.bremersee.authman.model.OAuth2ScopeVisibility;
import org.bremersee.authman.security.core.SecurityHelper;
import org.bremersee.authman.validation.ValidationProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.domain.Sort.Direction;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * @author Christian Bremer
 */
@Component("oauth2ScopeService")
@Slf4j
public class OAuth2ScopeServiceImpl implements OAuth2ScopeService {

  private static final Set<String> AVAILABLE_LANGUAGES = Arrays.stream(
      Locale.getAvailableLocales()).map(Locale::getLanguage).collect(Collectors.toSet());

  private final ValidationProperties validationProperties;

  private final OAuth2ScopeRepository scopeRepository;

  private final OAuth2ScopeMapper scopeMapper;

  private final OAuth2ClientRepository clientRepository;

  @Autowired
  public OAuth2ScopeServiceImpl(
      final ValidationProperties validationProperties,
      OAuth2ScopeRepository scopeRepository,
      OAuth2ScopeMapper scopeMapper,
      OAuth2ClientRepository clientRepository) {

    this.validationProperties = validationProperties;
    this.scopeRepository = scopeRepository;
    this.scopeMapper = scopeMapper;
    this.clientRepository = clientRepository;
  }

  private void validateScope(@NotNull final OAuth2ScopeDto scope) {
    if (!StringUtils.hasText(scope.getScope())
        || !validationProperties.getScopeNamePattern().matcher(scope.getScope()).matches()) {
      throw new InvalidScopeNameException(scope.getScope());
    }

    if (!StringUtils.hasText(scope.getDefaultLanguage())
        || !AVAILABLE_LANGUAGES.contains(scope.getDefaultLanguage())) {
      throw new InvalidLanguageException(scope.getDefaultLanguage());
    }

    String defaultDescription = scope.getDescriptions().get(scope.getDefaultLanguage());
    if (!StringUtils.hasText(defaultDescription)
        || !validationProperties.getScopeDescriptionPattern().matcher(defaultDescription)
        .matches()) {
      defaultDescription = scope.getDescription();
      if (!StringUtils.hasText(defaultDescription)
          || !validationProperties.getScopeDescriptionPattern().matcher(defaultDescription)
          .matches()) {
        throw new DescriptionRequiredException();
      } else {
        scope.getDescriptions().put(scope.getDefaultLanguage(), defaultDescription);
      }
    }

    (new HashSet<>(scope.getDescriptions().keySet())).forEach(language -> {
      if (!AVAILABLE_LANGUAGES.contains(language)
          || !StringUtils.hasText(scope.getDescriptions().get(language))
          || !validationProperties.getScopeDescriptionPattern().matcher(
          scope.getDescriptions().get(language)).matches()) {
        scope.getDescriptions().remove(language);
      }
    });

    if (scope.getVisibility() == null) {
      scope.setVisibility(OAuth2ScopeVisibility.PUBLIC);
    } else if (!SecurityHelper.isCurrentUserAdmin()
        && scope.getVisibility().equals(OAuth2ScopeVisibility.ADMIN)) {
      scope.setVisibility(OAuth2ScopeVisibility.PRIVATE);
    }
  }

  @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_DEVELOPER')")
  @Override
  public String createScope(@NotNull final OAuth2ScopeDto scope) {

    log.info("Creating scope [{}] ...", scope);

    validateScope(scope);

    if (scopeRepository.countByScope(scope.getScope()) > 0) {
      throw new AlreadyExistsException();
    }
    OAuth2Scope entity = new OAuth2Scope();
    scopeMapper.updateEntity(scope, entity);
    entity = scopeRepository.save(entity);

    log.info("Scope [{}] successfully created (id={})", entity.getId());
    return entity.getId();
  }

  @Override
  public Page<OAuth2ScopeDto> getScopes(
      final String search,
      final Pageable pageable,
      final Locale locale) {

    log.info("Getting scopes [search = {}, pageable = {}].", search, pageable);
    final Pageable p = pageable != null ? pageable : PageRequest
        .of(0, Integer.MAX_VALUE, Sort.by(Direction.ASC, "scope"));
    Page<OAuth2Scope> entityPage = scopeRepository.findVisibleScopes(search, p);
    return entityPage.map(oAuth2Scope -> scopeMapper.mapToDto(oAuth2Scope, locale));
  }

  @Override
  public OAuth2ScopeDto getScopeById(@NotNull final String id, final Locale locale) {
    log.info("Getting scope [id = {}].", id);
    return scopeRepository
        .findById(id)
        .map(oAuth2Scope -> scopeMapper.mapToDto(oAuth2Scope, locale))
        .orElseThrow(NotFoundException::new);
  }

  @Override
  public OAuth2ScopeDto getScope(@NotNull final String scope, final Locale locale) {
    log.info("Getting scope [scope = {}].", scope);
    return scopeRepository
        .findByScope(scope)
        .map(oAuth2Scope -> scopeMapper.mapToDto(oAuth2Scope, locale))
        .orElseThrow(NotFoundException::new);
  }

  @Override
  public boolean isScopeExisting(@NotNull final String scope) {
    final boolean exists = scopeRepository.countByScope(scope) > 0;
    log.info("Scope [{}] exists? {}", scope, exists);
    return exists;
  }

  @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_DEVELOPER')")
  @Override
  public void updateScope(
      @NotNull final String scopeName,
      @NotNull final OAuth2ScopeDto scope) {

    log.info("Updating scope [name = {}, scope = {}].", scopeName, scope);

    scope.setScope(scopeName);
    validateScope(scope);

    OAuth2Scope scopeEntity = scopeRepository
        .findByScope(scopeName)
        .orElseThrow(ForbiddenException::new);
    if (SecurityHelper.isCurrentUserAdmin()
        || SecurityHelper.isCurrentUserName(scopeEntity.getCreatedBy())) {
      scopeMapper.updateEntity(scope, scopeEntity);
      scopeRepository.save(scopeEntity);
    } else {
      log.error("Updating scope [{}] failed: Forbidden.", scopeName);
      throw new ForbiddenException();
    }
  }

  @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_DEVELOPER')")
  @Override
  public boolean deleteScopeById(@NotNull final String id) {

    log.info("Deleting scope with id [{}].", id);
    OAuth2Scope scopeEntity = scopeRepository
        .findById(id)
        .orElseThrow(ForbiddenException::new);
    return doDeleteScope(scopeEntity);
  }

  @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_DEVELOPER')")
  @Override
  public boolean deleteScope(@NotNull final String scope) {

    log.info("Deleting scope [{}].", scope);
    OAuth2Scope scopeEntity = scopeRepository
        .findByScope(scope)
        .orElseThrow(ForbiddenException::new);
    return doDeleteScope(scopeEntity);
  }

  private boolean doDeleteScope(@NotNull final OAuth2Scope scopeEntity) {

    if (!(SecurityHelper.isCurrentUserAdmin()
        || SecurityHelper.isCurrentUserName(scopeEntity.getCreatedBy()))) {
      log.error("Deleting scope [{}] failed: Forbidden.", scopeEntity.getScope());
      throw new ForbiddenException();
    }
    if (clientRepository.countByScopeContains(scopeEntity.getScope()) > 0) {
      log.error("Deleting scope [{}] failed: It is referenced by one or more oauth2 clients.",
          scopeEntity.getScope());
      return false;
    }
    scopeRepository.delete(scopeEntity);
    log.info("Scope [{}] successfully deleted.", scopeEntity.getScope());
    return true;
  }

}

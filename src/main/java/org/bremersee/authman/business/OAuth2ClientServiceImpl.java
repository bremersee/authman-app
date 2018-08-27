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

import javax.validation.constraints.NotNull;
import lombok.extern.slf4j.Slf4j;
import org.bremersee.authman.AuthorizationServerProperties;
import org.bremersee.authman.domain.OAuth2Client;
import org.bremersee.authman.domain.OAuth2ClientRepository;
import org.bremersee.authman.domain.OAuth2ScopeRepository;
import org.bremersee.authman.exception.AlreadyExistsException;
import org.bremersee.authman.exception.AuthorizedGrantTypeRequiredException;
import org.bremersee.authman.exception.ForbiddenException;
import org.bremersee.authman.exception.InvalidClientDisplayNameException;
import org.bremersee.authman.exception.InvalidClientIdException;
import org.bremersee.authman.exception.NotFoundException;
import org.bremersee.authman.exception.PasswordTooWeakException;
import org.bremersee.authman.exception.RegisteredRedirectUriRequiredException;
import org.bremersee.authman.exception.ScopeRequiredException;
import org.bremersee.authman.mapper.OAuth2ClientMapper;
import org.bremersee.authman.model.OAuth2ClientDto;
import org.bremersee.authman.security.core.RoleConstants;
import org.bremersee.authman.security.core.SecurityHelper;
import org.bremersee.authman.security.crypto.password.PasswordEncoder;
import org.bremersee.authman.security.crypto.password.PasswordEncoderImpl;
import org.bremersee.authman.security.crypto.password.PasswordEncoderProperties;
import org.bremersee.authman.validation.ValidationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.domain.Sort.Direction;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * @author Christian Bremer
 */
@Component("oauth2ClientService")
@EnableConfigurationProperties(AuthorizationServerProperties.class)
@Slf4j
public class OAuth2ClientServiceImpl implements OAuth2ClientService {

  private final ValidationProperties validationProperties;

  private final AuthorizationServerProperties authorizationServerProperties;

  private final RoleService roleService;

  private final OAuth2ScopeRepository scopeRepository;

  private final OAuth2ClientRepository clientRepository;

  private final OAuth2ClientMapper clientMapper;

  private final PasswordEncoder passwordEncoder;

  private final PasswordEncoder clearPasswordEncoder;

  public OAuth2ClientServiceImpl(
      final ValidationProperties validationProperties,
      final AuthorizationServerProperties authorizationServerProperties,
      final RoleService roleService,
      final OAuth2ScopeRepository scopeRepository,
      final OAuth2ClientRepository clientRepository,
      final OAuth2ClientMapper clientMapper,
      final PasswordEncoder passwordEncoder) {

    this.validationProperties = validationProperties;
    this.authorizationServerProperties = authorizationServerProperties;
    this.roleService = roleService;
    this.scopeRepository = scopeRepository;
    this.clientRepository = clientRepository;
    this.clientMapper = clientMapper;
    this.passwordEncoder = passwordEncoder;

    PasswordEncoderProperties pep = new PasswordEncoderProperties();
    pep.setAlgorithm("clear");
    pep.setStoreNoEncryptionFlag(true);
    clearPasswordEncoder = new PasswordEncoderImpl(pep);
  }

  private void validate( // NOSONAR
      @NotNull final OAuth2ClientDto client,
      final boolean forCreation) {

    if (!StringUtils.hasText(client.getClientId())
        || !validationProperties.getClientIdPattern().matcher(client.getClientId()).matches()) {
      throw new InvalidClientIdException(client.getClientId());
    }
    if (forCreation && clientRepository.countByClientId(client.getClientId()) > 0) {
      throw new AlreadyExistsException();
    }
    if (!StringUtils.hasText(client.getClientSecret())
        || !validationProperties.getClientSecretPattern().matcher(
        client.getClientSecret()).matches()) {
      throw new PasswordTooWeakException();
    }

    // remove empty or invalid values
    client.getAuthorizedGrantTypes().removeIf(s -> s == null || s.trim().length() == 0);
    client.getAutoApproveScopes().removeIf(s -> s == null || s.trim().length() == 0);
    client.getRegisteredRedirectUri().removeIf(s -> s == null || s.trim().length() == 0);
    client.getScope().removeIf(scopeRepository::isNotVisible);

    // Remove all entries that are not supported.
    client.getAuthorizedGrantTypes().removeIf(
        s -> !AuthorizationServerProperties.getAuthorizationGrantTypes().keySet().contains(s));

    if (!SecurityHelper.isCurrentUserAdmin()) {

      client.setClientSecretEncrypted(false);
      client.setAccessTokenValiditySeconds(null);
      client.setRefreshTokenValiditySeconds(null);
      client.getAutoApproveScopes().clear();
      client.getAuthorizedGrantTypes().removeIf(
          s -> !authorizationServerProperties.getDevelopersAuthorizationGrantTypes().contains(s));
      if (client.getRegisteredRedirectUri().isEmpty()) {
        throw new RegisteredRedirectUriRequiredException();
      }

    } else {

      if (client.getAutoApproveScopes().contains("true")) {
        if (client.getAutoApproveScopes().size() > 1) {
          client.getAutoApproveScopes().clear();
          client.getAutoApproveScopes().add("true");
        }
      } else {
        client.getAutoApproveScopes().removeIf(
            s -> !client.getScope().contains(s));
      }
    }

    if (client.getAuthorizedGrantTypes().isEmpty()) {
      throw new AuthorizedGrantTypeRequiredException();
    }

    if (client.getScope().isEmpty()) {
      throw new ScopeRequiredException();
    }

    if (!StringUtils.hasText(client.getDisplayName())
        || !validationProperties.getClientNamePattern().matcher(client.getDisplayName())
        .matches()) {
      throw new InvalidClientDisplayNameException(client.getDisplayName());
    }
  }

  @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_DEVELOPER')")
  @Override
  public OAuth2ClientDto createClient(@NotNull final OAuth2ClientDto client) {

    log.info("Creating client [{}] ...", client);

    validate(client, true);

    OAuth2Client clientEntity = new OAuth2Client();
    clientMapper.updateEntity(client, clientEntity);
    clientEntity.setClientId(client.getClientId());
    if (Boolean.TRUE.equals(client.getClientSecretEncrypted())) {
      clientEntity.setClientSecretEncrypted(true);
      clientEntity.setClientSecret(passwordEncoder.encode(client.getClientSecret()));
    } else {
      clientEntity.setClientSecretEncrypted(false);
      clientEntity.setClientSecret(clearPasswordEncoder.encode(client.getClientSecret()));
    }
    clientEntity = clientRepository.save(clientEntity);

    // save role
    roleService.addRole(client.getClientId(), RoleConstants.OAUTH2_CLIENT_ROLE);

    final OAuth2ClientDto result = clientMapper.mapToDto(clientEntity);
    log.info("Client [{}] successfully created.", result);
    return result;
  }

  @Override
  public Page<OAuth2ClientDto> getClients(final String search, final Pageable pageable) {

    log.info("Getting clients [search = {}, pageable = {}].", search, pageable);
    final Pageable p = pageable != null ? pageable : PageRequest
        .of(0, Integer.MAX_VALUE, Sort.by(Direction.ASC, "clientId"));
    Page<OAuth2Client> entityPage;
    if (StringUtils.hasText(search)) {
      if (SecurityHelper.isCurrentUserAdmin()) {
        entityPage = clientRepository.findBySearchRegex(search, p);
      } else {
        entityPage = clientRepository.findByCreatedByAndSearchRegex(
            SecurityHelper.getCurrentUserName(), search, p);
      }
    } else {
      if (SecurityHelper.isCurrentUserAdmin()) {
        entityPage = clientRepository.findAll(p);
      } else {
        entityPage = clientRepository.findByCreatedBy(SecurityHelper.getCurrentUserName(), p);
      }
    }
    return entityPage.map(clientMapper::mapToDto);
  }

  @PostAuthorize("hasRole('ROLE_ADMIN') or authentication.name == returnObject.createdBy")
  @Override
  public OAuth2ClientDto getClient(@NotNull final String clientId) {
    log.info("Getting client [clientId = {}].", clientId);
    return clientRepository
        .findByClientId(clientId).map(clientMapper::mapToDto)
        .orElseThrow(NotFoundException::new);
  }

  @Override
  public boolean isClientExisting(@NotNull final String clientId) {
    final boolean exists = clientRepository.countByClientId(clientId) > 0;
    log.info("Client [{}] exists? {}", clientId, exists);
    return exists;
  }

  @Override
  public OAuth2ClientDto updateClient(
      @NotNull final String clientId,
      @NotNull final OAuth2ClientDto client) {

    log.info("Updating client [clientId = {}, client = {}].", clientId, client);

    validate(client, false);

    OAuth2Client clientEntity = clientRepository
        .findByClientId(clientId)
        .orElseThrow(ForbiddenException::new);

    if (SecurityHelper.isCurrentUserAdmin()
        || SecurityHelper.isCurrentUserName(clientEntity.getCreatedBy())) {

      client.setClientId(clientId);
      validate(client, false);

      clientMapper.updateEntity(client, clientEntity);
      OAuth2ClientDto result = clientMapper.mapToDto(clientRepository.save(clientEntity));
      log.info("Client successfully updated: {}", result);
      return result;
    }

    log.error("Updating client [{}] failed: Forbidden.", clientId);
    throw new ForbiddenException();
  }

  @Override
  public void deleteClient(@NotNull String clientId) {

    log.info("Deleting client [{}].", clientId);
    OAuth2Client clientEntity = clientRepository
        .findByClientId(clientId)
        .orElseThrow(ForbiddenException::new);
    if (SecurityHelper.isCurrentUserAdmin()
        || SecurityHelper.isCurrentUserName(clientEntity.getCreatedBy())) {
      roleService.deleteRoles(clientId);
      clientRepository.delete(clientEntity);
    } else {
      log.error("Deleting client [{}] failed: Forbidden.", clientId);
      throw new ForbiddenException();
    }
  }

}

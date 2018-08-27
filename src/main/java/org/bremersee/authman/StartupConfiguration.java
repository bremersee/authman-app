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

package org.bremersee.authman;

import javax.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.bremersee.authman.business.OAuth2ClientService;
import org.bremersee.authman.business.OAuth2ScopeService;
import org.bremersee.authman.business.RoleService;
import org.bremersee.authman.business.UserProfileService;
import org.bremersee.authman.model.OAuth2ScopeDto;
import org.bremersee.authman.security.core.RoleConstants;
import org.bremersee.authman.security.core.SecurityHelper;
import org.bremersee.authman.security.core.context.RunAsCallbackWithoutResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * @author Christian Bremer
 */
@Configuration
@EnableConfigurationProperties({
    StartupProperties.class,
    AuthorizationServerProperties.class
})
@Slf4j
public class StartupConfiguration {

  private final StartupProperties startupProperties;

  private final AuthorizationServerProperties authorizationServerProperties;

  private final UserProfileService userService;

  private final RoleService roleService;

  private final OAuth2ScopeService scopeService;

  private final OAuth2ClientService clientService;

  @Autowired
  public StartupConfiguration(StartupProperties startupProperties,
      AuthorizationServerProperties authorizationServerProperties,
      UserProfileService userService, RoleService roleService,
      OAuth2ScopeService scopeService,
      OAuth2ClientService clientService) {

    this.startupProperties = startupProperties;
    this.authorizationServerProperties = authorizationServerProperties;
    this.userService = userService;
    this.roleService = roleService;
    this.scopeService = scopeService;
    this.clientService = clientService;
  }

  @PostConstruct
  public void init() {
    SecurityHelper.runAs(
        startupProperties.getAdmin().getUserName(),
        new String[]{RoleConstants.ADMIN_ROLE},
        new Initializer());


  }

  private class Initializer extends RunAsCallbackWithoutResult {

    @Override
    public void run() {
      createAdmin();
      createActuator();
      createScopes();
      createClients();
    }

    private void createAdmin() {

      log.info("Creating admin ...");

      if (!userService.isUserProfileExisting(startupProperties.getAdmin().getUserName())) {
        userService.createUserProfile(
            startupProperties.getAdmin(), false, false);
      }

      final String adminName = startupProperties.getAdmin().getUserName();
      roleService.addRole(adminName, RoleConstants.USER_ROLE);
      roleService.addRole(adminName, RoleConstants.DEVELOPER_ROLE);
      roleService.addRole(adminName, RoleConstants.ADMIN_ROLE);
      roleService.addRole(adminName, RoleConstants.SAMBA_ADMIN_ROLE);
    }

    private void createActuator() {

      log.info("Creating actuator ...");

      if (!userService.isUserProfileExisting(startupProperties.getActuator().getUserName())) {
        userService.createUserProfile(
            startupProperties.getActuator(), false, false);
      }

      final String actuatorName = startupProperties.getActuator().getUserName();
      roleService.addRole(actuatorName, RoleConstants.ACTUATOR_ROLE);
    }

    private void createScopes() {

      log.info("Creating scopes ...");

      final OAuth2ScopeDto read = authorizationServerProperties.getProfileReadScope();
      if (!scopeService.isScopeExisting(read.getScope())) {
        scopeService.createScope(read);
      }

      final OAuth2ScopeDto write = authorizationServerProperties.getProfileWriteScope();
      if (!scopeService.isScopeExisting(write.getScope())) {
        scopeService.createScope(write);
      }

      final OAuth2ScopeDto samba = authorizationServerProperties.getSambaAdminScope();
      if (!scopeService.isScopeExisting(samba.getScope())) {
        scopeService.createScope(samba);
      }

      for (OAuth2ScopeDto scope : authorizationServerProperties.getOtherScopes()) {
        if (!scopeService.isScopeExisting(scope.getScope())) {
          scopeService.createScope(scope);
        }
      }
    }

    private void createClients() {

      log.info("Creating clients ...");

      if (!clientService.isClientExisting(
          authorizationServerProperties.getInternalClient().getClientId())) {
        clientService.createClient(authorizationServerProperties.getInternalClient());
      }

      if (!clientService.isClientExisting(
          authorizationServerProperties.getSambaConnectorClient().getClientId())) {
        clientService.createClient(authorizationServerProperties.getSambaConnectorClient());
      }
      roleService.addRole(
          authorizationServerProperties.getSambaConnectorClient().getClientId(),
          RoleConstants.SAMBA_ADMIN_ROLE);
    }
  }

}

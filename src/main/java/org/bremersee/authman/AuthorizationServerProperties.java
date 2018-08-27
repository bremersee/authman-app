/*
 * Copyright 2015 the original author or authors.
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

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.bremersee.authman.model.OAuth2ClientDto;
import org.bremersee.authman.model.OAuth2ScopeDto;
import org.bremersee.authman.model.OAuth2ScopeVisibility;
import org.bremersee.utils.PasswordUtils;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * @author Christian Bremer
 */
@ConfigurationProperties("bremersee.authorization-server")
@Getter
@Setter
@ToString(exclude = {"jwtKeyStorePassword", "jwtKeyPairPassword"})
public class AuthorizationServerProperties {

  public static final String AUTHORIZATION_CODE = "authorization_code";

  public static final String CLIENT_CREDENTIALS = "client_credentials";

  public static final String REFRESH_TOKEN = "refresh_token";

  public static final String PASSWORD_CREDENTIALS = "password"; // NOSONAR

  public static final String IMPLICIT = "implicit";

  private static final Map<String, String> authorizationGrantTypes;

  private static final String PROFILE_READ_SCOPE = "profile";

  private static final String PROFILE_WRITE_SCOPE = "profile:write";

  private static final String PROFILE_SYNC_SCOPE = "profile:sync";

  private static final String SAMBA_ADMIN_SCOPE = "samba:admin";

  static {
    final Map<String, String> grantTypes = new LinkedHashMap<>();
    grantTypes.put(AUTHORIZATION_CODE, "authorization.grant.type.authorization_code");
    grantTypes.put(CLIENT_CREDENTIALS, "authorization.grant.type.client_credentials");
    grantTypes.put(REFRESH_TOKEN, "authorization.grant.type.refresh_token");
    grantTypes.put(PASSWORD_CREDENTIALS, "authorization.grant.type.password_credentials");
    grantTypes.put(IMPLICIT, "authorization.grant.type.implicit");
    authorizationGrantTypes = Collections.unmodifiableMap(grantTypes);
  }

  /**
   * Returns a map with possible authorization grant types. The key is the grant type, the value is
   * the message source code.
   *
   * @return a map with possible authorization grant types
   */
  public static Map<String, String> getAuthorizationGrantTypes() {
    return authorizationGrantTypes;
  }

  private String jwtSigningKey;

  private String jwtVerifierKey;

  private String jwtKeyStoreLocation;

  private String jwtKeyStorePassword;

  private String jwtKeyPairAlias;

  private String jwtKeyPairPassword;

  private String realm = "oauth2/client";

  private boolean allowFormAuthenticationForClients = false;

  private String tokenKeyAccess = "permitAll()"; // original: denyAll()

  private String checkTokenAccess = "isAuthenticated()"; // original: denyAll()

  private boolean sslOnly = false;

  private boolean handleApprovalRevocationsAsExpiry = false;

  private Set<String> defaultAuthorizationGrantTypes = new LinkedHashSet<>();

  private Set<String> developersAuthorizationGrantTypes = new LinkedHashSet<>();

  private String noScopeDescriptionAvailable = "Sorry, there's no description of this scope.";

  private OAuth2ScopeDto profileReadScope = new OAuth2ScopeDto();

  private OAuth2ScopeDto profileWriteScope = new OAuth2ScopeDto();

  private OAuth2ScopeDto profileSyncScope = new OAuth2ScopeDto();

  private OAuth2ScopeDto sambaAdminScope = new OAuth2ScopeDto();

  private List<OAuth2ScopeDto> otherScopes = new ArrayList<>();

  private Set<String> defaultScopes = new LinkedHashSet<>();

  private OAuth2ClientDto internalClient = new OAuth2ClientDto();

  private OAuth2ClientDto listenerClient = new OAuth2ClientDto();

  private OAuth2ClientDto sambaConnectorClient = new OAuth2ClientDto();

  private List<OAuth2ClientDto> otherClients = new ArrayList<>();

  public AuthorizationServerProperties() {
    defaultAuthorizationGrantTypes.add(AUTHORIZATION_CODE);
    defaultAuthorizationGrantTypes.add(IMPLICIT);

    developersAuthorizationGrantTypes.addAll(defaultAuthorizationGrantTypes);
    developersAuthorizationGrantTypes.add(CLIENT_CREDENTIALS); // machine-to-machine
    developersAuthorizationGrantTypes.add(REFRESH_TOKEN);

    profileReadScope.setScope(PROFILE_READ_SCOPE);
    profileReadScope.setVisibility(OAuth2ScopeVisibility.PUBLIC);
    profileReadScope.setDefaultLanguage("en");
    profileReadScope.getDescriptions().put("en", "Read your user profile.");
    profileReadScope.getDescriptions().put("de", "Dein Benutzerprofil lesen.");

    profileWriteScope.setScope(PROFILE_WRITE_SCOPE);
    profileWriteScope.setVisibility(OAuth2ScopeVisibility.PUBLIC);
    profileWriteScope.setDefaultLanguage("en");
    profileWriteScope.getDescriptions().put("en", "Write your user profile.");
    profileWriteScope.getDescriptions().put("de", "Dein Benutzerprofil schreiben.");

    profileSyncScope.setScope(PROFILE_SYNC_SCOPE);
    profileSyncScope.setVisibility(OAuth2ScopeVisibility.ADMIN);
    profileSyncScope.setDefaultLanguage("en");
    profileSyncScope.getDescriptions().put("en", "Synchronize an user profile.");
    profileSyncScope.getDescriptions().put("de", "Ein Benutzerprofil synchronisieren.");

    sambaAdminScope.setScope(SAMBA_ADMIN_SCOPE);
    sambaAdminScope.setVisibility(OAuth2ScopeVisibility.ADMIN);
    sambaAdminScope.setDefaultLanguage("en");
    sambaAdminScope.getDescriptions().put("en", "Administrate the Samba AD.");
    sambaAdminScope.getDescriptions().put("de", "Samba AD administrieren.");

    defaultScopes.add(PROFILE_READ_SCOPE);

    listenerClient.setDisplayName("Authman Listener Client");
    listenerClient.setClientId("authman-listener-client");
    listenerClient.setClientSecret(PasswordUtils
        .createRandomClearPassword(64, false, false));
    listenerClient.setClientSecretEncrypted(false);
    listenerClient.getAuthorizedGrantTypes().add(CLIENT_CREDENTIALS);
    listenerClient.getAuthorizedGrantTypes().add(PASSWORD_CREDENTIALS);
    listenerClient.getScope().add(PROFILE_SYNC_SCOPE);
    listenerClient.getAutoApproveScopes().add(Boolean.TRUE.toString());

    sambaConnectorClient.setDisplayName("Samba Connector Client");
    sambaConnectorClient.setClientId("smb-con-client");
    sambaConnectorClient.setClientSecret(PasswordUtils
        .createRandomClearPassword(64, false, false));
    sambaConnectorClient.setClientSecretEncrypted(false);
    sambaConnectorClient.getAuthorizedGrantTypes().add(CLIENT_CREDENTIALS);
    sambaConnectorClient.getAuthorizedGrantTypes().add(PASSWORD_CREDENTIALS);
    sambaConnectorClient.getScope().add(PROFILE_READ_SCOPE);
    sambaConnectorClient.getScope().add(PROFILE_WRITE_SCOPE);
    sambaConnectorClient.getScope().add(SAMBA_ADMIN_SCOPE);
    sambaConnectorClient.getAutoApproveScopes().add(Boolean.TRUE.toString());

    internalClient.setDisplayName("Internal OAuth2 Client");
    internalClient.setClientId("internal-client");
    internalClient.setClientSecret("secret4INTERNAL");
    internalClient.setClientSecretEncrypted(false);
    internalClient.getAuthorizedGrantTypes().add(AUTHORIZATION_CODE); // -> response_type=code
    internalClient.getAuthorizedGrantTypes().add(CLIENT_CREDENTIALS);
    internalClient.getAuthorizedGrantTypes().add(REFRESH_TOKEN);
    internalClient.getAuthorizedGrantTypes().add(PASSWORD_CREDENTIALS);
    internalClient.getAuthorizedGrantTypes().add(IMPLICIT); // -> response_type=token
    internalClient.getScope().add(PROFILE_READ_SCOPE);
    internalClient.getScope().add(PROFILE_WRITE_SCOPE);
    internalClient.getAutoApproveScopes().add(Boolean.TRUE.toString());

  }
}
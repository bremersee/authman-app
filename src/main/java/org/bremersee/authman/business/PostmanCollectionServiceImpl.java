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

import static org.bremersee.authman.AuthorizationServerProperties.AUTHORIZATION_CODE;
import static org.bremersee.authman.AuthorizationServerProperties.CLIENT_CREDENTIALS;
import static org.bremersee.authman.AuthorizationServerProperties.IMPLICIT;
import static org.bremersee.authman.AuthorizationServerProperties.PASSWORD_CREDENTIALS;
import static org.bremersee.authman.AuthorizationServerProperties.REFRESH_TOKEN;

import com.netflix.hystrix.contrib.javanica.annotation.HystrixCommand;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import javax.validation.constraints.NotNull;
import lombok.extern.slf4j.Slf4j;
import org.bremersee.authman.domain.OAuth2Client;
import org.bremersee.authman.domain.OAuth2ClientRepository;
import org.bremersee.authman.exception.ForbiddenException;
import org.bremersee.authman.model.postman.Auth;
import org.bremersee.authman.model.postman.Basic;
import org.bremersee.authman.model.postman.Body;
import org.bremersee.authman.model.postman.Collection;
import org.bremersee.authman.model.postman.Event;
import org.bremersee.authman.model.postman.Header;
import org.bremersee.authman.model.postman.Info;
import org.bremersee.authman.model.postman.Item;
import org.bremersee.authman.model.postman.OAuth2;
import org.bremersee.authman.model.postman.Query;
import org.bremersee.authman.model.postman.Request;
import org.bremersee.authman.model.postman.Url;
import org.bremersee.authman.model.postman.UrlEncoded;
import org.bremersee.authman.security.core.SecurityHelper;
import org.bremersee.authman.security.crypto.password.PasswordEncoder;
import org.bremersee.authman.security.crypto.password.PasswordEncoderImpl;
import org.bremersee.authman.security.crypto.password.PasswordEncoderProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * @author Christian Bremer
 */
@Component
@Slf4j
public class PostmanCollectionServiceImpl implements PostmanCollectionService {

  // see http://schema.getpostman.com/json/collection/v2.1.0/collection.json

  private static final String RESPONSE_TYPE = "response_type";

  private static final String TOKEN = "token";

  private static final String CODE = "code";

  private static final String CLIENT_ID = "client_id";

  private static final String REDIRECT_URI = "redirect_uri";

  private static final String GRANT_TYPE = "grant_type";

  private static final String GRANT__TYPE = "grantType"; // NOSONAR

  private static final String CLIENT_SECRET = "clientSecret";

  private static final String USERNAME = "username";

  private static final String PASSWORD = "password"; // NOSONAR

  private static final String CONTENT_TYPE = "Content-Type";

  private static final String ACCEPT = "Accept";

  private final OAuth2ClientRepository clientRepository;

  private final PasswordEncoder passwordEncoder;

  @Value("${server.servlet.context-path:}")
  private String contextPath = "";

  @Value("${bremersee.postman-collection.oauth-path:/oauth}")
  private String oauthPath = "/oauth"; // NOSONAR

  @Value("${bremersee.postman-collection.authorize-path:/authorize}")
  private String authorizePath = "/authorize"; // NOSONAR

  @Value("${bremersee.postman-collection.token-path:/token}")
  private String tokenPath = "/token"; // NOSONAR

  @Value("${bremersee.postman-collection.me-path:/api/me}")
  private String mePath = "/api/me"; // NOSONAR

  @Value("${bremersee.postman-collection.fallback-redirect:http://localhost:6080}")
  private String fallbackCallbackUrl = "http://localhost:6080";

  @Autowired
  public PostmanCollectionServiceImpl(
      final OAuth2ClientRepository clientRepository) {

    this.clientRepository = clientRepository;
    final PasswordEncoderProperties pep = new PasswordEncoderProperties();
    pep.setAlgorithm("clear");
    pep.setStoreNoEncryptionFlag(true);
    this.passwordEncoder = new PasswordEncoderImpl(pep);
  }

  public Collection emptyCollection(
      @NotNull String clientId,
      @NotNull String scheme,
      @NotNull String host,
      int port) {

    log.info("Generation EMPTY postman collection of client [{}].", clientId);
    return new Collection();
  }

  @HystrixCommand(fallbackMethod = "emptyCollection")
  @Override
  public Collection generatePostmanCollection(
      @NotNull String clientId,
      @NotNull String scheme,
      @NotNull String host,
      int port) {

    log.info("Generation postman collection of client [{}].", clientId);

    OAuth2Client clientEntity = clientRepository
        .findByClientId(clientId)
        .orElseThrow(ForbiddenException::new);

    if (SecurityHelper.isCurrentUserAdmin()
        || SecurityHelper.isCurrentUserName(clientEntity.getCreatedBy())) {

      final String displayName = StringUtils.hasText(clientEntity.getDisplayName())
          ? clientEntity.getDisplayName() : clientEntity.getClientId();

      final Info info = new Info();
      info.setName("OAuth2 of '" + displayName + "'");
      info.setDescription("OAuth2 Flows and Me Resource.");

      final Collection collection = new Collection();
      collection.setInfo(info);
      collection.getItem().addAll(generatePostmanItems(clientEntity, scheme, host, port));
      collection.setAuth(oauth2(clientEntity, scheme, host, port));
      collection.setEvent(Event.defaultEmptyEvents());
      return collection;

    } else {
      log.error("Generating postman collection of client [{}] failed: Forbidden.", clientId);
      throw new ForbiddenException();
    }
  }

  private List<Item> generatePostmanItems(
      OAuth2Client client,
      String scheme,
      String host,
      int port) {

    final List<Item> items = new ArrayList<>();
    items.addAll(generatePostmanItemAuthorizationCode(client, scheme, host, port));
    items.addAll(generatePostmanItemImplicit(client, scheme, host, port));
    items.addAll(generatePostmanItemPasswordCredentials(client, scheme, host, port));
    items.addAll(generatePostmanItemClientCredentials(client, scheme, host, port));
    items.add(generateMeItem(client, scheme, host, port));
    items.addAll(generateRefreshToken(client, scheme, host, port));
    return items;
  }

  private List<Item> generatePostmanItemAuthorizationCode(
      OAuth2Client client,
      String scheme,
      String host,
      int port) {

    if (!client.getAuthorizedGrantTypes()
        .contains(AUTHORIZATION_CODE)) {
      return Collections.emptyList();
    }

    final Url url0 = new Url();
    url0.setRaw(getUrlPrefix(scheme, host, port) + contextPath + oauthPath + authorizePath
        + "?response_type=code"
        + "&client_id=" + client.getClientId()
        + "&redirect_uri=" + getCallbackUrl(client));
    url0.setProtocol(scheme);
    url0.setHost(getHost(host));
    url0.setPort(String.valueOf(port));
    url0.setPath(getPath(contextPath, oauthPath, authorizePath));
    url0.setQuery(
        Url.buildQuery(
            new Query(RESPONSE_TYPE, CODE, true),
            new Query(CLIENT_ID, client.getClientId(), true),
            new Query(REDIRECT_URI, getCallbackUrl(client), true)
        )
    );

    final Request req0 = new Request();
    req0.setAuth(Auth.newNoAuth());
    req0.setMethod("GET");
    req0.setBody(new Body());
    req0.setUrl(url0);
    req0.setDescription("Call the URL in your browser and copy the code to '"
        + "Authorization Code (Part 2: Post Code)'.");

    final Item item0 = new Item();
    item0.setName("Authorization Code (Part 1: Browser)");
    item0.setRequest(req0);

    final Auth auth1 = new Auth();
    auth1.setType(Auth.TYPE_BASIC);
    auth1.setBasic(Basic.newBasicAuth(client.getClientId(), getClientSecret(client)));

    final Body body = Body.newUrlEncodedBody(
        new UrlEncoded(GRANT_TYPE, AUTHORIZATION_CODE, "", UrlEncoded.TYPE_TEXT),
        new UrlEncoded(CLIENT_ID, client.getClientId(), "", UrlEncoded.TYPE_TEXT),
        new UrlEncoded(REDIRECT_URI, getCallbackUrl(client), "", UrlEncoded.TYPE_TEXT),
        new UrlEncoded(CODE, "{{authorization_code}}", "", UrlEncoded.TYPE_TEXT)
    );

    final Url url1 = new Url();
    url1.setRaw(getUrlPrefix(scheme, host, port) + contextPath + oauthPath + tokenPath);
    url1.setProtocol(scheme);
    url1.setHost(getHost(host));
    url1.setPort(String.valueOf(port));
    url1.setPath(getPath(contextPath, oauthPath, tokenPath));

    final Request req1 = new Request();
    req1.setAuth(auth1);
    req1.setMethod("POST");
    req1.getHeader().add(new Header(
        CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)); // NOSONAR
    req1.setBody(body);
    req1.setUrl(url1);
    req1.setDescription("Exchanges the code and gets the token.");

    final Item item1 = new Item();
    item1.setName("Authorization Code (Part 2: Post Code)");
    item1.setRequest(req1);

    List<Item> items = new ArrayList<>(2);
    items.add(item0);
    items.add(item1);
    return items;
  }

  private List<Item> generatePostmanItemImplicit(
      OAuth2Client client,
      String scheme,
      String host,
      int port) {

    if (!client.getAuthorizedGrantTypes()
        .contains(IMPLICIT)) {
      return Collections.emptyList();
    }

    final Url url = new Url();
    url.setRaw(getUrlPrefix(scheme, host, port) + contextPath + oauthPath + authorizePath
        + "?response_type=token"
        + "&client_id=" + client.getClientId()
        + "&redirect_uri=" + getCallbackUrl(client));
    url.setProtocol(scheme);
    url.setHost(getHost(host));
    url.setPort(String.valueOf(port));
    url.setPath(getPath(contextPath, oauthPath, authorizePath));
    url.setQuery(
        Url.buildQuery(
            new Query(RESPONSE_TYPE, TOKEN, true),
            new Query(CLIENT_ID, client.getClientId(), true),
            new Query(REDIRECT_URI, getCallbackUrl(client), true)
        )
    );

    final Request request = new Request();
    request.setAuth(Auth.newNoAuth());
    request.setMethod("GET");
    request.setBody(new Body());
    request.setUrl(url);
    request.setDescription("Call the URL in your browser. You should get the token "
        + "as fragment of the redirect URL.");

    final Item item = new Item();
    item.setName("Implicit (Browser)");
    item.setRequest(request);
    return Collections.singletonList(item);
  }

  private List<Item> generatePostmanItemPasswordCredentials(
      OAuth2Client client,
      String scheme,
      String host,
      int port) {

    if (!client.getAuthorizedGrantTypes()
        .contains(PASSWORD_CREDENTIALS)) {
      return Collections.emptyList();
    }

    final Auth auth = new Auth();
    auth.setType(Auth.TYPE_BASIC);
    auth.setBasic(Basic.newBasicAuth(client.getClientId(), getClientSecret(client)));

    final Body body = Body.newUrlEncodedBody(
        new UrlEncoded(GRANT_TYPE, PASSWORD_CREDENTIALS, "", UrlEncoded.TYPE_TEXT),
        new UrlEncoded(USERNAME, "{{username}}", "", UrlEncoded.TYPE_TEXT),
        new UrlEncoded(PASSWORD, "{{password}}", "", UrlEncoded.TYPE_TEXT));

    final Url url = new Url();
    url.setRaw(getUrlPrefix(scheme, host, port) + contextPath + oauthPath + tokenPath);
    url.setProtocol(scheme);
    url.setHost(getHost(host));
    url.setPort(String.valueOf(port));
    url.setPath(getPath(contextPath, oauthPath, tokenPath));

    final Request request = new Request();
    request.setAuth(auth);
    request.setMethod("POST");
    request.getHeader().add(new Header(ACCEPT, MediaType.APPLICATION_JSON_VALUE));
    request.getHeader().add(new Header(CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE));
    request.setBody(body);
    request.setUrl(url);
    request.setDescription("Enter user name and password of a user to obtain an access token.");

    final Item item = new Item();
    item.setName("Password Credentials");
    item.setRequest(request);
    return Collections.singletonList(item);
  }

  private List<Item> generatePostmanItemClientCredentials(
      OAuth2Client client,
      String scheme,
      String host,
      int port) {

    if (!client.getAuthorizedGrantTypes()
        .contains(CLIENT_CREDENTIALS)) {
      return Collections.emptyList();
    }

    final Auth auth = new Auth();
    auth.setType(Auth.TYPE_BASIC);
    auth.setBasic(Basic.newBasicAuth(client.getClientId(), getClientSecret(client)));

    final Body body = Body.newUrlEncodedBody(
        new UrlEncoded(GRANT_TYPE, CLIENT_CREDENTIALS, "", UrlEncoded.TYPE_TEXT));

    final Url url = new Url();
    url.setRaw(getUrlPrefix(scheme, host, port) + contextPath + oauthPath + tokenPath);
    url.setProtocol(scheme);
    url.setHost(getHost(host));
    url.setPort(String.valueOf(port));
    url.setPath(getPath(contextPath, oauthPath, tokenPath));

    final Request request = new Request();
    request.setAuth(auth);
    request.setMethod("POST");
    request.getHeader().add(new Header(ACCEPT, MediaType.APPLICATION_JSON_VALUE));
    request.getHeader().add(new Header(CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE));
    request.setBody(body);
    request.setUrl(url);
    request.setDescription("Invoke the request and obtain an access token of the client.");

    final Item item = new Item();
    item.setName("Client Credentials");
    item.setRequest(request);
    return Collections.singletonList(item);
  }

  private List<Item> generateRefreshToken(
      OAuth2Client client,
      String scheme,
      String host,
      int port) {

    if (!client.getAuthorizedGrantTypes().contains(REFRESH_TOKEN)) {
      return Collections.emptyList();
    }

    final Auth auth = new Auth();
    auth.setType(Auth.TYPE_BASIC);
    auth.setBasic(Basic.newBasicAuth(client.getClientId(), getClientSecret(client)));

    final Body body = Body.newUrlEncodedBody(
        new UrlEncoded(GRANT_TYPE, REFRESH_TOKEN, "", UrlEncoded.TYPE_TEXT),
        new UrlEncoded(
            "refresh_token", "{{refreshToken}}", "", UrlEncoded.TYPE_TEXT));

    final Url url = new Url();
    url.setRaw(getUrlPrefix(scheme, host, port) + contextPath + oauthPath + tokenPath);
    url.setProtocol(scheme);
    url.setHost(getHost(host));
    url.setPort(String.valueOf(port));
    url.setPath(getPath(contextPath, oauthPath, tokenPath));

    final Request request = new Request();
    request.setAuth(auth);
    request.setMethod("POST");
    request.getHeader().add(new Header(ACCEPT, MediaType.APPLICATION_JSON_VALUE));
    request.getHeader().add(new Header(CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE));
    request.setBody(body);
    request.setUrl(url);
    request.setDescription("Invoke the request and obtain a refreshed token.");

    final Item item = new Item();
    item.setName("Refresh Token");
    item.setRequest(request);
    return Collections.singletonList(item);
  }

  private Item generateMeItem(
      OAuth2Client client,
      String scheme,
      String host,
      int port) {

    final Url url = new Url();
    url.setRaw(getUrlPrefix(scheme, host, port) + contextPath + mePath);
    url.setProtocol(scheme);
    url.setHost(getHost(host));
    url.setPort(String.valueOf(port));
    url.setPath(getPath(contextPath, mePath));

    final Request request = new Request();
    request.setAuth(oauth2(client, scheme, host, port));
    request.setMethod("GET");
    request.getHeader().add(new Header(ACCEPT, MediaType.APPLICATION_JSON_VALUE));
    request.setBody(new Body());
    request.setUrl(url);
    request.setDescription("Gets the me resource.");

    final Item item = new Item();
    item.setName("Me");
    item.setRequest(request);
    return item;
  }

  private String getCallbackUrl(OAuth2Client client) {
    if (client.getRegisteredRedirectUri().isEmpty()) {
      return fallbackCallbackUrl;
    }
    return new ArrayList<>(client.getRegisteredRedirectUri()).get(0);
  }

  private String getUrlPrefix(String scheme, String host, int port) {
    return scheme + "://" + host + ((port == 80 || port == 443) ? "" : ":" + port);
  }

  private List<String> getPath(String... paths) {

    List<String> list = new ArrayList<>();
    if (paths != null && paths.length > 0) {
      for (String p : paths) {
        while (p.startsWith("/")) {
          p = p.substring(1);
        }
        String[] tmp = StringUtils.delimitedListToStringArray(p, "/");
        for (String path : tmp) {
          if (StringUtils.hasText(path)) {
            list.add(path);
          }
        }
      }
    }
    return list;
  }

  private List<String> getHost(String host) {
    return Arrays.asList(StringUtils.delimitedListToStringArray(host, "."));
  }

  private String getClientSecret(OAuth2Client client) {
    if (client.isClientSecretEncrypted()) {
      return "*****";
    }
    return passwordEncoder.getClearPassword(client.getClientSecret());
  }

  private Auth oauth2(
      OAuth2Client client,
      String scheme,
      String host,
      int port) {

    final Auth auth = new Auth();
    auth.setType(Auth.TYPE_OAUTH2);

    final OAuth2 grantTypeAuth;
    final OAuth2 clientSecretAuth;
    final OAuth2 usernameAuth;
    final OAuth2 passwordAuth;
    if (client.getAuthorizedGrantTypes().contains(AUTHORIZATION_CODE)) {
      grantTypeAuth = new OAuth2(GRANT__TYPE, AUTHORIZATION_CODE, OAuth2.TYPE_STRING);
      clientSecretAuth = new OAuth2(CLIENT_SECRET, getClientSecret(client), OAuth2.TYPE_STRING);
      usernameAuth = new OAuth2(USERNAME, null, OAuth2.TYPE_ANY);
      passwordAuth = new OAuth2(PASSWORD, null, OAuth2.TYPE_ANY);
    } else if (client.getAuthorizedGrantTypes().contains(IMPLICIT)) {
      grantTypeAuth = new OAuth2(GRANT__TYPE, IMPLICIT, OAuth2.TYPE_STRING);
      clientSecretAuth = new OAuth2(CLIENT_SECRET, null, OAuth2.TYPE_ANY);
      usernameAuth = new OAuth2(USERNAME, null, OAuth2.TYPE_ANY);
      passwordAuth = new OAuth2(PASSWORD, null, OAuth2.TYPE_ANY);
    } else if (client.getAuthorizedGrantTypes().contains(PASSWORD_CREDENTIALS)) {
      grantTypeAuth = new OAuth2(GRANT__TYPE, "password_credentials", OAuth2.TYPE_STRING);
      clientSecretAuth = new OAuth2(CLIENT_SECRET, getClientSecret(client), OAuth2.TYPE_STRING);
      usernameAuth = new OAuth2(USERNAME, "{{username}}", OAuth2.TYPE_STRING);
      passwordAuth = new OAuth2(PASSWORD, "{{password}}", OAuth2.TYPE_STRING);
    } else if (client.getAuthorizedGrantTypes().contains(CLIENT_CREDENTIALS)) {
      grantTypeAuth = new OAuth2(GRANT__TYPE, CLIENT_CREDENTIALS, OAuth2.TYPE_STRING);
      clientSecretAuth = new OAuth2(CLIENT_SECRET, getClientSecret(client), OAuth2.TYPE_STRING);
      usernameAuth = new OAuth2(USERNAME, null, OAuth2.TYPE_ANY);
      passwordAuth = new OAuth2(PASSWORD, null, OAuth2.TYPE_ANY);
    } else {
      grantTypeAuth = new OAuth2(GRANT__TYPE, null, OAuth2.TYPE_ANY);
      clientSecretAuth = new OAuth2(CLIENT_SECRET, null, OAuth2.TYPE_ANY);
      usernameAuth = new OAuth2(USERNAME, null, OAuth2.TYPE_ANY);
      passwordAuth = new OAuth2(PASSWORD, null, OAuth2.TYPE_ANY);
    }

    auth.setOauth2(OAuth2.oauth2(
        new OAuth2("accessToken", "{{accessToken}}", OAuth2.TYPE_STRING),
        new OAuth2("tokenType", "bearer", OAuth2.TYPE_STRING),
        new OAuth2("addTokenTo", "header", OAuth2.TYPE_STRING),
        new OAuth2("callBackUrl", getCallbackUrl(client), OAuth2.TYPE_STRING),
        new OAuth2("authUrl",
            scheme + "://" + host + ":" + port + contextPath + oauthPath + authorizePath,
            OAuth2.TYPE_STRING),
        new OAuth2("accessTokenUrl",
            scheme + "://" + host + ":" + port + contextPath + oauthPath + tokenPath,
            OAuth2.TYPE_STRING),
        new OAuth2("clientId", client.getClientId(), OAuth2.TYPE_STRING),
        clientSecretAuth,
        new OAuth2("clientAuth", "body", OAuth2.TYPE_STRING), // alt: header
        grantTypeAuth,
        new OAuth2(
            "scope",
            StringUtils.collectionToDelimitedString(client.getScope(), " "),
            OAuth2.TYPE_STRING),
        usernameAuth,
        passwordAuth,
        new OAuth2("redirectUri", getCallbackUrl(client), OAuth2.TYPE_STRING),
        new OAuth2("refreshToken", null, OAuth2.TYPE_ANY)
    ));
    return auth;
  }

}

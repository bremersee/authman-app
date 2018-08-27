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

import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.constraints.NotNull;
import lombok.extern.slf4j.Slf4j;
import org.bremersee.authman.domain.OAuth2ForeignToken;
import org.bremersee.authman.domain.OAuth2ForeignTokenRepository;
import org.bremersee.authman.mapper.OAuth2ForeignTokenMapper;
import org.bremersee.authman.mapper.OAuth2ForeignTokenMapperImpl;
import org.bremersee.authman.security.authentication.CodeExchangeResponse;
import org.bremersee.authman.security.authentication.ForeignUserProfile;
import org.bremersee.authman.security.authentication.ForeignUserProfileDefaultRequestor;
import org.bremersee.authman.security.authentication.ForeignUserProfileParser;
import org.bremersee.authman.security.authentication.OAuth2AuthenticationProperties;
import org.bremersee.authman.security.authentication.OAuth2StateCache;
import org.bremersee.authman.security.core.SecurityHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * @author Christian Bremer
 */
@Controller
@Slf4j
public class OAuth2MergeController extends AbstractController {

  private static final String PROFILE_REDIRECT = "redirect:/profile";

  private static final String CONNECT_ERROR_CODE = "i18n.oauth2.connect.profile.error";

  private final Map<String, OAuth2AuthenticationProperties> providerProperties = new HashMap<>();

  private final Map<String, ForeignUserProfileParser> userProfileParsers = new HashMap<>();

  private final OAuth2ForeignTokenRepository oauth2TokenRepository;

  private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

  private RestTemplateBuilder restTemplateBuilder = new RestTemplateBuilder();

  private OAuth2ForeignTokenMapper foreignTokenMapper = new OAuth2ForeignTokenMapperImpl();

  @Autowired
  public OAuth2MergeController(
      final LocaleResolver localeResolver,
      final List<OAuth2AuthenticationProperties> providerProperties,
      final List<ForeignUserProfileParser> userProfileParsers,
      final OAuth2ForeignTokenRepository oauth2TokenRepository) {

    super(localeResolver);
    providerProperties.forEach(
        oAuth2AuthenticationProperties -> OAuth2MergeController.this.providerProperties.put(
            oAuth2AuthenticationProperties.getProvider(),
            oAuth2AuthenticationProperties));
    userProfileParsers.forEach(
        userProfileParser -> OAuth2MergeController.this.userProfileParsers.put(
            userProfileParser.getProvider(), userProfileParser));
    this.oauth2TokenRepository = oauth2TokenRepository;
  }

  @Autowired(required = false)
  public void setRestTemplateBuilder(final RestTemplateBuilder restTemplateBuilder) {
    if (restTemplateBuilder != null) {
      this.restTemplateBuilder = restTemplateBuilder;
    }
  }

  @Autowired(required = false)
  public void setForeignTokenMapper(
      final OAuth2ForeignTokenMapper foreignTokenMapper) {
    if (foreignTokenMapper != null) {
      this.foreignTokenMapper = foreignTokenMapper;
    }
  }

  private void addFlashAttribute(
      final HttpServletRequest request,
      final RedirectAttributes redirectAttributes,
      final String msgCode,
      final Object[] args,
      final RedirectMessageType msgType) {
    final String msg = getMessageSource().getMessage(
        msgCode,
        args == null ? new Object[]{} : args,
        resolveLocale(request));
    final RedirectMessage rmsg = new RedirectMessage(msg, msgType);
    redirectAttributes.addFlashAttribute(RedirectMessage.ATTRIBUTE_NAME, rmsg);

  }

  @GetMapping(path = "/profile/oauth2-connect")
  public void redirectToOAuth2Login(
      @RequestParam(name = "provider") final String provider,
      final HttpServletRequest request,
      final HttpServletResponse response) throws IOException {

    log.info("Connecting profile with provider {}", provider);
    final OAuth2AuthenticationProperties properties = providerProperties.get(provider);
    if (properties == null) {
      log.warn("msg=[Provider is unsupported.] provider=[{}]", provider);
      redirectStrategy.sendRedirect(request, response, "../profile");
      return;
    }

    final String state = UUID.randomUUID().toString().replace("-", "");
    final String url = properties.buildLoginUrl(
        properties.getRedirectUriProfileConnect(),
        null,
        null,
        state,
        null);
    new OAuth2StateCache(properties.getStateKeyName()).saveState(request, state);
    redirectStrategy.sendRedirect(request, response, url);
  }

  @GetMapping(path = "/{provider}/callback/profile")
  public String exchangeCode(
      @PathVariable("provider") final String provider,
      final HttpServletRequest request,
      final RedirectAttributes redirectAttributes) {

    log.info("Exchange code from provider {}", provider);
    final OAuth2AuthenticationProperties properties = providerProperties.get(provider);
    final ForeignUserProfileParser parser = userProfileParsers.get(provider);
    if (properties == null || parser == null) {
      addFlashAttribute(request, redirectAttributes,
          "i18n.oauth2.provider.unsupported", new Object[]{provider},
          RedirectMessageType.WARNING);
      return PROFILE_REDIRECT;
    }

    final String error = request.getParameter(properties.getResponseErrorParameter());
    if (StringUtils.hasText(error)) {
      log.error("msg=[An error occurred while accessing oauth2 provider.] provider=[{}] error=[{}]",
          provider, error);
      addFlashAttribute(request, redirectAttributes,
          CONNECT_ERROR_CODE, new Object[]{},
          RedirectMessageType.WARNING);
      return PROFILE_REDIRECT;
    }

    final OAuth2StateCache stateCache = new OAuth2StateCache(properties.getStateKeyName());
    final String savedState = stateCache.getState(request);
    final String state = request.getParameter(properties.getResponseStateParameter());
    stateCache.removeState(request);

    if (!StringUtils.hasText(savedState) || !savedState.equals(state)) {
      log.error("msg=[The oauth2 states don't match.] savedState=[{}] providedState=[{}]",
          savedState, state);
      addFlashAttribute(request, redirectAttributes,
          CONNECT_ERROR_CODE, new Object[]{},
          RedirectMessageType.WARNING);
      return PROFILE_REDIRECT;
    }

    final String code = request.getParameter(properties.getResponseCodeParameter());
    if (!StringUtils.hasText(code)) {
      log.error("msg=[There is no code parameter.]");
      addFlashAttribute(request, redirectAttributes,
          CONNECT_ERROR_CODE, new Object[]{},
          RedirectMessageType.WARNING);
      return PROFILE_REDIRECT;
    }

    final CodeExchangeResponse codeResponse = exchangeCode(code, properties);
    final ForeignUserProfile foreignUserProfile = new ForeignUserProfileDefaultRequestor(
        properties, parser)
        .restTemplateBuilder(restTemplateBuilder)
        .getForeignUserProfile(codeResponse);

    final String userName = SecurityHelper.getCurrentUserName();
    if (!StringUtils.hasText(userName)) {
      log.error("msg=[There is no user name.]");
      return PROFILE_REDIRECT;
    }

    OAuth2ForeignToken entity = oauth2TokenRepository
        .findByProviderAndForeignUserName(provider, foreignUserProfile.getName())
        .orElse(new OAuth2ForeignToken());

    if (entity.isNew() || userName.equals(entity.getUserName())) {
      foreignTokenMapper.updateForeignToken(
          entity,
          provider,
          userName,
          foreignUserProfile.getName(),
          properties.scopes(),
          codeResponse);
      oauth2TokenRepository.save(entity);
    } else {
      log.warn("msg=[The foreign profile is already connected to an user.] "
              + "currentUser=[{}] otherUser=[{}] foreignUser=[{}]",
          userName, entity.getUserName(), entity.getForeignUserName());
      addFlashAttribute(request, redirectAttributes,
          "i18n.oauth2.connect.profile.already.connected", new Object[]{},
          RedirectMessageType.WARNING);
      return PROFILE_REDIRECT;
    }

    addFlashAttribute(request, redirectAttributes,
        "i18n.oauth2.connect.profile.successfully.connected", new Object[]{},
        RedirectMessageType.SUCCESS);
    return PROFILE_REDIRECT;
  }

  private CodeExchangeResponse exchangeCode(
      @NotNull final String code,
      @NotNull final OAuth2AuthenticationProperties properties) {

    final RestTemplate restTemplate = restTemplateBuilder.build();
    final Map<String, Object> params = properties.buildExchangeCodeRequestParameters(
        code, properties.getRedirectUriProfileConnect(), null);
    final String url = properties.getTokenUrlTemplate();
    final HttpMethod httpMethod = properties.getTokenMethod();
    HttpEntity<String> httpEntity = new HttpEntity<>("");
    for (Map.Entry<String, String> headerEntry : properties.getTokenHeaders().entrySet()) {
      httpEntity.getHeaders().set(headerEntry.getKey(), headerEntry.getValue());
    }
    final ResponseEntity<CodeExchangeResponse> response = restTemplate
        .exchange(url, httpMethod, httpEntity,
            CodeExchangeResponse.class, params);
    return response.getBody();
  }

  @PostMapping(path = "/profile/oauth2-disconnect")
  public String disconnectProfile(
      @RequestParam(name = "provider") final String provider,
      final HttpServletRequest request,
      final RedirectAttributes redirectAttributes) {

    oauth2TokenRepository.deleteByProviderAndUserName(
        provider, SecurityHelper.getCurrentUserName());
    addFlashAttribute(request, redirectAttributes,
        "i18n.oauth2.connect.profile.successfully.disconnected", new Object[]{},
        RedirectMessageType.SUCCESS);
    return PROFILE_REDIRECT;
  }

  public void requestAccessToken(
      @RequestParam(name = "provider") final String provider,
      final HttpServletRequest request) {

    final String userName = SecurityHelper.getCurrentUserName();
    final Optional<OAuth2ForeignToken> foreignToken = oauth2TokenRepository
        .findByProviderAndUserName(provider, userName);
    if (foreignToken.isPresent()
        && (new Date(System.currentTimeMillis() - 10000L))
        .before(foreignToken.get().getExpiresAt())) {

      // return the access token
    } else {

      // return login url
    }
  }

}

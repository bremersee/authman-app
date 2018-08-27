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
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import javax.servlet.http.HttpServletRequest;
import javax.validation.constraints.NotNull;
import lombok.AccessLevel;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.bremersee.authman.AuthorizationServerProperties;
import org.bremersee.authman.business.OAuth2ClientService;
import org.bremersee.authman.business.OAuth2ScopeService;
import org.bremersee.authman.controller.AbstractController;
import org.bremersee.authman.model.OAuth2ClientDto;
import org.bremersee.authman.model.SelectOptionDto;
import org.bremersee.authman.security.core.SecurityHelper;
import org.bremersee.authman.security.crypto.password.PasswordEncoder;
import org.bremersee.authman.security.crypto.password.PasswordEncoderImpl;
import org.bremersee.authman.security.crypto.password.PasswordEncoderProperties;
import org.bremersee.authman.validation.ValidationProperties;
import org.bremersee.utils.PasswordUtils;
import org.springframework.data.util.Pair;
import org.springframework.web.servlet.LocaleResolver;

/**
 * @author Christian Bremer
 */
public abstract class AbstractOAuth2ClientController extends AbstractController {

  private static final String ENCRYPTED_PASSWORD_PLACEHOLDER = "**************"; // NOSONAR

  @Getter(AccessLevel.PROTECTED)
  private final ValidationProperties validationProperties;

  @Getter(AccessLevel.PROTECTED)
  private final AuthorizationServerProperties authorizationServerProperties;

  @Getter(AccessLevel.PROTECTED)
  private final OAuth2ScopeService scopeService;

  @Getter(AccessLevel.PROTECTED)
  private final OAuth2ClientService clientService;

  private final PasswordEncoder passwordEncoder;

  public AbstractOAuth2ClientController(
      @NotNull final ValidationProperties validationProperties,
      @NotNull final AuthorizationServerProperties authorizationServerProperties,
      @NotNull final OAuth2ScopeService scopeService,
      @NotNull final OAuth2ClientService clientService,
      @NotNull final LocaleResolver localeResolver) {
    super(localeResolver);
    this.validationProperties = validationProperties;
    this.authorizationServerProperties = authorizationServerProperties;
    this.scopeService = scopeService;
    this.clientService = clientService;

    final PasswordEncoderProperties pep = new PasswordEncoderProperties();
    pep.setAlgorithm("clear");
    pep.setStoreNoEncryptionFlag(false);
    this.passwordEncoder = new PasswordEncoderImpl(pep);
  }

  List<SelectOptionDto> chronoUnits(HttpServletRequest request) {
    final ChronoUnit[] chronoUnits = new ChronoUnit[]{
        ChronoUnit.SECONDS,
        ChronoUnit.MINUTES,
        ChronoUnit.HOURS,
        ChronoUnit.DAYS,
        ChronoUnit.WEEKS,
        ChronoUnit.MONTHS
    };
    return Arrays.stream(chronoUnits).map(chronoUnit -> new SelectOptionDto(
        chronoUnit.name(),
        getMessageSource().getMessage(
            "chrono.unit." + chronoUnit.name().toLowerCase(),
            new Object[0],
            chronoUnit.toString(),
            resolveLocale(request)),
        false)).collect(Collectors.toList());
  }

  List<SelectOptionDto> availableScopes(final HttpServletRequest request) {
    final Locale locale = resolveLocale(request);
    final String defaultLanguage = Locale.getDefault().getLanguage();
    final String language = locale != null ? locale.getLanguage() : defaultLanguage;
    return scopeService.getScopes(null, null, resolveLocale(request))
        .getContent()
        .stream()
        .map(oAuth2ScopeDto -> new SelectOptionDto(
            oAuth2ScopeDto.getScope(),
            oAuth2ScopeDto.getDescriptions().getOrDefault(
                language, oAuth2ScopeDto.getDescription()),
            authorizationServerProperties.getDefaultScopes().contains(oAuth2ScopeDto.getScope())))
        .collect(Collectors.toList());
  }

  List<SelectOptionDto> grantTypes(HttpServletRequest request) {
    final Locale locale = resolveLocale(request);
    final List<SelectOptionDto> options = new ArrayList<>();
    for (Map.Entry<String, String> grantEntry : AuthorizationServerProperties
        .getAuthorizationGrantTypes().entrySet()) {
      final String grantType = grantEntry.getKey();
      if (SecurityHelper.isCurrentUserAdmin() ||
          authorizationServerProperties.getDevelopersAuthorizationGrantTypes().contains(
              grantType)) {
        final String code = grantEntry.getValue();
        final String displayValue = getMessageSource()
            .getMessage(code, new Object[0], grantType, locale);
        options.add(new SelectOptionDto(grantType, displayValue, false));
      }
    }
    return options;
  }

  OAuth2ClientDto mapToDto(@NotNull final OAuth2ClientCommand cmd) {
    final OAuth2ClientDto dto = new OAuth2ClientDto();
    mapToDto(cmd, dto, true);
    return dto;
  }

  void mapToDto(
      @NotNull OAuth2ClientCommand source,
      @NotNull OAuth2ClientDto destination,
      boolean mapClientSecret) {

    destination.setAccessTokenValiditySeconds(
        toSeconds(source.getAccessTokenValidity(), source.getAccessTokenValidityChronoUnit()));

    destination.getAuthorizedGrantTypes().clear();
    destination.getAuthorizedGrantTypes().addAll(source.getAuthorizedGrantTypes());

    destination.getAutoApproveScopes().clear();
    destination.getAutoApproveScopes().addAll(source.getAutoApproveScopes());

    destination.setClientId(source.getClientId());
    if (mapClientSecret) {
      destination.setClientSecret(source.getClientSecret());
      destination.setClientSecretEncrypted(source.isClientSecretEncrypted());
    }
    destination.setDisplayName(source.getDisplayName());

    destination.setRefreshTokenValiditySeconds(
        toSeconds(source.getRefreshTokenValidity(), source.getRefreshTokenValidityChronoUnit()));

    destination.getRegisteredRedirectUri().clear();
    destination.getRegisteredRedirectUri().addAll(source.getRegisteredRedirectUri());

    destination.getScope().clear();
    destination.getScope().addAll(source.getScope());
  }

  OAuth2ClientCommand mapToCommand(@NotNull final OAuth2ClientDto dto) {
    final OAuth2ClientCommand cmd = new OAuth2ClientCommand();

    final Pair<Integer, String> accessTokenValidity = tokenValiditySecondsToValueAndUnit(
        dto.getAccessTokenValiditySeconds(), 12, ChronoUnit.HOURS);
    cmd.setAccessTokenValidity(accessTokenValidity.getFirst());
    cmd.setAccessTokenValidityChronoUnit(accessTokenValidity.getSecond());

    cmd.getAuthorizedGrantTypes().addAll(dto.getAuthorizedGrantTypes());
    cmd.getAutoApproveScopes().addAll(dto.getAutoApproveScopes());
    cmd.setClientId(dto.getClientId());
    if (passwordEncoder.isEncrypted(dto.getClientSecret())) {
      cmd.setClientSecret(ENCRYPTED_PASSWORD_PLACEHOLDER);
    } else {
      cmd.setClientSecret(passwordEncoder.getClearPassword(dto.getClientSecret()));
    }
    cmd.setClientSecretEncrypted(Boolean.TRUE.equals(dto.getClientSecretEncrypted()));
    cmd.setDisplayName(dto.getDisplayName());

    final Pair<Integer, String> refreshTokenValidity = tokenValiditySecondsToValueAndUnit(
        dto.getRefreshTokenValiditySeconds(), 30, ChronoUnit.DAYS);
    cmd.setRefreshTokenValidity(refreshTokenValidity.getFirst());
    cmd.setRefreshTokenValidityChronoUnit(refreshTokenValidity.getSecond());

    cmd.getRegisteredRedirectUri().addAll(dto.getRegisteredRedirectUri());
    cmd.getScope().addAll(dto.getScope());
    return cmd;
  }

  private Integer toSeconds(int value, String chronoUnit) {
    if (!SecurityHelper.isCurrentUserAdmin()) {
      return null;
    }
    try {
      final Duration duration = Duration.of(value, ChronoUnit.valueOf(chronoUnit));
      return (int) (duration.toMillis() / 1000L);

    } catch (RuntimeException re) {
      return null;
    }
  }

  private Pair<Integer, String> tokenValiditySecondsToValueAndUnit(
      final Integer seconds, final int defaultValue, @NotNull final ChronoUnit defaultUnit) {
    if (seconds == null) {
      return Pair.of(defaultValue, defaultUnit.name());
    }
    if (seconds <= 0) {
      return Pair.of(-1, ChronoUnit.SECONDS.name());
    }

    final int min = 60;
    final int hour = min * 60;
    final int day = hour * 24;
    final int week = day * 7;
    final int month = day * 30;
    if (seconds / month > 0 && seconds % month == 0) {
      return Pair.of(seconds / month, ChronoUnit.MONTHS.name());
    } else if (seconds / week > 0 && seconds % week == 0) {
      return Pair.of(seconds / week, ChronoUnit.WEEKS.name());
    } else if (seconds / day > 0 && seconds % day == 0) {
      return Pair.of(seconds / day, ChronoUnit.DAYS.name());
    } else if (seconds / hour > 0 && seconds % hour == 0) {
      return Pair.of(seconds / hour, ChronoUnit.HOURS.name());
    } else if (seconds / min > 0 && seconds % min == 0) {
      return Pair.of(seconds / min, ChronoUnit.MINUTES.name());
    }
    return Pair.of(seconds, ChronoUnit.SECONDS.name());
  }

  OAuth2ClientCommand newOAuth2ClientCommand() {
    final OAuth2ClientCommand cmd = new OAuth2ClientCommand();
    cmd.getScope().addAll(authorizationServerProperties.getDefaultScopes());
    cmd.getAuthorizedGrantTypes().addAll(
        authorizationServerProperties.getDefaultAuthorizationGrantTypes());
    cmd.setAccessTokenValidity(12);
    cmd.setAccessTokenValidityChronoUnit(ChronoUnit.HOURS.name());
    cmd.setRefreshTokenValidity(30);
    cmd.setRefreshTokenValidityChronoUnit(ChronoUnit.DAYS.name());
    cmd.getRegisteredRedirectUri().add("");
    return cmd;
  }

  @SuppressWarnings("WeakerAccess")
  @Getter
  @Setter
  @ToString(exclude = {"clientSecret"})
  @EqualsAndHashCode
  @NoArgsConstructor
  public static class OAuth2ClientCommand implements Serializable {

    private static final long serialVersionUID = -7763403003626140406L;

    private String clientId = UUID.randomUUID().toString();

    private String clientSecret = PasswordUtils.createRandomClearPassword(
        32, false, false);

    private boolean clientSecretEncrypted = false;

    private String displayName;

    //private List<String> resourceIds = new ArrayList<>(); // NOSONAR

    private List<String> scope = new ArrayList<>();

    private List<String> authorizedGrantTypes = new ArrayList<>();

    private List<String> registeredRedirectUri = new ArrayList<>();

    private int accessTokenValidity = 12;

    private String accessTokenValidityChronoUnit = ChronoUnit.HOURS.name();

    private int refreshTokenValidity = 30;

    private String refreshTokenValidityChronoUnit = ChronoUnit.DAYS.name();

    private List<String> autoApproveScopes = new ArrayList<>();

  }

}

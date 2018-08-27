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

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TimeZone;
import javax.servlet.http.HttpServletRequest;
import javax.validation.constraints.NotNull;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;
import org.bremersee.authman.model.SelectOptionDto;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.i18n.TimeZoneAwareLocaleContext;
import org.springframework.util.StringUtils;
import org.springframework.web.servlet.LocaleContextResolver;
import org.springframework.web.servlet.LocaleResolver;

/**
 * @author Christian Bremer
 */
public abstract class AbstractController implements MessageSourceAware {

  @Getter(AccessLevel.PROTECTED)
  @Setter
  private MessageSource messageSource;

  @Getter(AccessLevel.PROTECTED)
  private LocaleResolver localeResolver;

  public AbstractController(@NotNull final LocaleResolver localeResolver) {
    this.localeResolver = localeResolver;
  }

  protected Locale resolveLocale(@NotNull final HttpServletRequest request) {
    return localeResolver.resolveLocale(request);
  }

  protected TimeZone resolveTimeZone(@NotNull final HttpServletRequest request) {

    TimeZone timeZone = null;
    if (localeResolver instanceof LocaleContextResolver
        && ((LocaleContextResolver) localeResolver)
        .resolveLocaleContext(request) instanceof TimeZoneAwareLocaleContext) {

      timeZone = ((TimeZoneAwareLocaleContext) ((LocaleContextResolver) localeResolver)
          .resolveLocaleContext(request)).getTimeZone();
    }
    if (timeZone == null) {
      timeZone = TimeZone.getTimeZone("Europe/Berlin");
    }
    return timeZone;
  }

  protected List<SelectOptionDto> getAvailableLocales(@NotNull final Locale inLocale) {

    final Locale[] locales = Locale.getAvailableLocales();
    final List<SelectOptionDto> localeOptions = new ArrayList<>(locales.length);
    SelectOptionDto first = null;
    for (final Locale locale : locales) {
      final SelectOptionDto so = new SelectOptionDto();
      if (locale.toString().length() == 5) {
        so.setValue(locale.toString());
        so.setDisplayValue(locale.getDisplayName(inLocale));
        if (locale.equals(inLocale)) {
          first = so;
        } else {
          localeOptions.add(so);
        }
      }
    }
    Collections.sort(localeOptions);
    if (first != null) {
      localeOptions.add(0, first);
    }
    return localeOptions;
  }

  protected List<SelectOptionDto> getAvailableLanguages(@NotNull final Locale inLocale) {

    final Set<String> languages = new HashSet<>();
    final Locale[] locales = Locale.getAvailableLocales();
    final List<SelectOptionDto> localeOptions = new ArrayList<>(locales.length);
    SelectOptionDto first = null;
    for (final Locale locale : locales) {
      final SelectOptionDto so = new SelectOptionDto();
      if (locale.getLanguage() != null && !languages.contains(locale.getLanguage())) {
        languages.add(locale.getLanguage());
        so.setValue(locale.getLanguage());
        so.setDisplayValue(locale.getDisplayLanguage(inLocale));
        if (locale.equals(inLocale)) {
          first = so;
        } else {
          localeOptions.add(so);
        }
      }
    }
    Collections.sort(localeOptions);
    if (first != null) {
      localeOptions.add(0, first);
    }
    return localeOptions;
  }

  protected List<SelectOptionDto> getAvailableTimeZones(
      @NotNull final Locale inLocale, final TimeZone defaultTimeZone) {

    final String[] ids = TimeZone.getAvailableIDs();
    final ArrayList<SelectOptionDto> options = new ArrayList<>(ids.length);
    SelectOptionDto first = null;
    for (final String id : ids) {
      final TimeZone tz = TimeZone.getTimeZone(id);
      final SelectOptionDto option = new SelectOptionDto();
      option.setValue(id);
      option.setDisplayValue(id + " (" + tz.getDisplayName(inLocale) + ")");
      if (defaultTimeZone != null && defaultTimeZone.getID().equals(id)) {
        first = option;
      } else {
        options.add(option);
      }
    }
    if (first != null) {
      options.add(0, first);
    }
    return options;
  }

  protected String urlEncode(final String value) {
    if (value == null) {
      return "";
    }
    try {
      return URLEncoder.encode(value, StandardCharsets.UTF_8.name());

    } catch (UnsupportedEncodingException e) {
      return value;
    }
  }

  protected String urlDecode(final String value) {
    if (value == null) {
      return "";
    }
    try {
      return URLDecoder.decode(value, StandardCharsets.UTF_8.name());

    } catch (UnsupportedEncodingException e) {
      return value;
    }
  }

  protected String normalizeDistinguishedName(final String dn) {
    if (!StringUtils.hasText(dn)) {
      return "";
    }
    final String[] parts = StringUtils.delimitedListToStringArray(dn, ",");
    final StringBuilder sb = new StringBuilder();
    int i = 0;
    for (final String part : parts) {
      if (i > 0) {
        sb.append(',');
      }
      final int index = part.indexOf('=');
      if (index <= 0) {
        sb.append(part);
      } else {
        sb.append(part.substring(0, index).trim().toLowerCase());
        sb.append("=");
        sb.append(part.substring(index+1).trim());
      }
      i++;
    }
    return sb.toString();
  }

}

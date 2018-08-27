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

package org.bremersee.authman.security.authentication.google;

import java.util.Locale;
import java.util.TimeZone;
import javax.validation.constraints.NotNull;
import org.apache.commons.lang3.LocaleUtils;
import org.bremersee.authman.security.authentication.ForeignUserProfileDocumentContext;
import org.springframework.util.StringUtils;

/**
 * @author Christian Bremer
 */
public class GoogleUserProfile extends ForeignUserProfileDocumentContext {

  private static final long serialVersionUID = 2884752443583330249L;

  @SuppressWarnings("WeakerAccess")
  public GoogleUserProfile(
      @NotNull byte[] foreignUserProfileBytes) {
    super(foreignUserProfileBytes);
  }

  @Override
  public String getDisplayName() {
    final String displayName = read("$['name']", String.class);
    if (StringUtils.hasText(displayName)) {
      return displayName;
    }
    return getFirstName() + " " + getLastName();
  }

  @Override
  public String getEmail() {
    return read("$['emails'][0]['value']", String.class);
  }

  @Override
  public Locale getLocale() {
    final String language = read("$['language']", String.class);
    if (language == null) {
      return null;
    }
    return LocaleUtils.toLocale(language.replace("-", "_"));
  }

  @Override
  public TimeZone getTimeZone() {
    return null;
  }

  @Override
  public String getName() {
    return read("$['id']", String.class);
  }

  @SuppressWarnings("WeakerAccess")
  public String getFirstName() {
    return read("$['name']['givenName']", String.class);
  }

  @SuppressWarnings("WeakerAccess")
  public String getLastName() {
    return read("$['name']['familyName']", String.class);
  }

  @SuppressWarnings("unused")
  public String getGender() {
    return read("$['gender']", String.class);
  }

  @SuppressWarnings("unused")
  public String getUrl() {
    return read("$['url']", String.class);
  }

  @SuppressWarnings("unused")
  public String getImageUrl() {
    return read("$['image']['url']", String.class);
  }

  @SuppressWarnings("unused")
  public boolean isDefaultImage() {
    return read("$['image']['isDefault']", Boolean.class);
  }

  @SuppressWarnings("unused")
  public boolean isVerified() {
    return read("$['verified']", Boolean.class);
  }

}

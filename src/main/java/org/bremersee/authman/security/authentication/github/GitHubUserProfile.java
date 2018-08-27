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

package org.bremersee.authman.security.authentication.github;

import java.util.Locale;
import java.util.TimeZone;
import javax.validation.constraints.NotNull;
import org.bremersee.authman.security.authentication.ForeignUserProfileDocumentContext;

/**
 * @author Christian Bremer
 */
public class GitHubUserProfile extends ForeignUserProfileDocumentContext {

  private static final long serialVersionUID = 2653625254386327666L;

  @SuppressWarnings("WeakerAccess")
  public GitHubUserProfile(
      @NotNull byte[] foreignUserProfileBytes) {
    super(foreignUserProfileBytes);
  }

  @Override
  public String getDisplayName() {
    return read("$.name", String.class);
  }

  @Override
  public String getEmail() {
    return read("$.email", String.class);
  }

  @Override
  public Locale getLocale() {
    return null;
  }

  @Override
  public TimeZone getTimeZone() {
    return null;
  }

  @Override
  public String getName() {
    return read("$.login", String.class);
  }
}

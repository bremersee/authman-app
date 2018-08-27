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

package org.bremersee.authman.security.web.savedrequest;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.servlet.http.Cookie;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.savedrequest.SavedRequest;

/**
 * @author Christian Bremer
 */
@RequiredArgsConstructor
public class SavedGetRequest implements SavedRequest {

  private static final long serialVersionUID = 421944667249519608L;

  @Getter
  @NonNull
  private final String redirectUrl;

  @Override
  public List<Cookie> getCookies() {
    return Collections.emptyList();
  }

  @Override
  public String getMethod() {
    return HttpMethod.GET.name();
  }

  @Override
  public List<String> getHeaderValues(String name) {
    return Collections.emptyList();
  }

  @Override
  public Collection<String> getHeaderNames() {
    return Collections.emptyList();
  }

  @Override
  public List<Locale> getLocales() {
    return Collections.emptyList();
  }

  @Override
  public String[] getParameterValues(String name) {
    return new String[0];
  }

  @Override
  public Map<String, String[]> getParameterMap() {
    return Collections.emptyMap();
  }
}

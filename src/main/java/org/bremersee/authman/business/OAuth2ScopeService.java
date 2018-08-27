/*
 * Copyright 2016 the original author or authors.
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

import java.util.List;
import java.util.Locale;
import javax.validation.constraints.NotNull;
import org.bremersee.authman.domain.OAuth2Scope;
import org.bremersee.authman.model.OAuth2ScopeDto;
import org.bremersee.authman.model.SelectOptionDto;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

/**
 * @author Christian Bremer
 */
public interface OAuth2ScopeService {

  String createScope(@NotNull OAuth2ScopeDto scope);

  Page<OAuth2ScopeDto> getScopes(String search, Pageable pageable, Locale locale);

  OAuth2ScopeDto getScopeById(@NotNull String id, Locale locale);

  OAuth2ScopeDto getScope(@NotNull String scope, Locale locale);

  boolean isScopeExisting(@NotNull String scope);

  void updateScope(@NotNull String scopeName, @NotNull OAuth2ScopeDto scope);

  boolean deleteScopeById(@NotNull String id);

  boolean deleteScope(@NotNull String scope);

}

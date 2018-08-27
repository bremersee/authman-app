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

package org.bremersee.authman.domain;

import java.util.List;
import java.util.Optional;
import org.springframework.data.mongodb.repository.MongoRepository;

/**
 * @author Christian Bremer
 */
public interface OAuth2ScopeRepository
    extends MongoRepository<OAuth2Scope, String>, OAuth2ScopeRepositoryCustom {

  //Page<OAuth2Scope> findByScopeLike(String scope, Pageable pageable);

  //Page<OAuth2Scope> findByVisibility(OAuth2ScopeVisibility visibility, Pageable pageable);

  //Page<OAuth2Scope> findByScopeLikeAndVisibility(String scope, OAuth2ScopeVisibility visibility, Pageable pageable);

  //Page<OAuth2Scope> findByVisibilityOrCreatedBy(OAuth2ScopeVisibility visibilityPublic, String createdBy, Pageable pageable);

  long countByScope(String scope);

  Optional<OAuth2Scope> findByScope(String scope);

  List<OAuth2Scope> findByScopeIn(List<String> scopes);

}

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

package org.bremersee.authman.domain;

import java.util.Optional;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;

/**
 * @author Christian Bremer
 */
public interface OAuth2ClientRepository extends MongoRepository<OAuth2Client, String> {

  long countByClientId(String clientId);

  Optional<OAuth2Client> findByClientId(String clientId);

  @Query("{ 'clientId': { $regex: ?0 } }")
  Page<OAuth2Client> findBySearchRegex(String searchRegex, Pageable pageable);

  Page<OAuth2Client> findByCreatedBy(String createdBy, Pageable pageable);

  @Query("{ 'createdBy': ?0, 'clientId': { $regex: ?1 } }")
  Page<OAuth2Client> findByCreatedByAndSearchRegex(String createdBy, String searchRegex,
      Pageable pageable);

  long countByScopeContains(String scope);

}

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

import java.util.Date;
import java.util.List;
import java.util.Optional;
import org.springframework.data.mongodb.repository.MongoRepository;

/**
 * @author Christian Bremer
 */
public interface OAuth2ApprovalRepository extends MongoRepository<OAuth2Approval, String> {

  List<OAuth2Approval> findByUserIdAndClientId(String userId, String clientId);

  Optional<OAuth2Approval> findByUserIdAndClientIdAndScope(String userId, String clientId,
      String scope);

  Long deleteByUserIdAndClientIdAndScope(String userId, String clientId, String scope);

  Long deleteByExpiresAtBefore(Date now);

}

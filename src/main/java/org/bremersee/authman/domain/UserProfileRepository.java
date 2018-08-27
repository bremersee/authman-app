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

import java.util.Optional;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;

/**
 * @author Christian Bremer
 */
public interface UserProfileRepository extends MongoRepository<UserProfile, String>,
    UserProfileRepositoryCustom {

  long countByUserName(String userName);

  long countByEmail(String email);

  Optional<UserProfile> findByUserName(String userName);

  Optional<UserProfile> findByEmail(String email);

  Optional<UserProfile> findByMobile(String mobile);

  /**
   * Find an user by user name or email address.
   *
   * @param login user name or email addrress
   * @return the user
   */
  @Query("{ $or: [ { 'userName': ?0 }, { 'email': ?0 } ] }")
  Optional<UserProfile> findByLogin(String login);

  @Query("{ $or: [ { 'userName': { $regex: ?0 } }, { 'displayName': { $regex: ?0 } }, { 'email': { $regex: ?0 } } ] }")
  Page<UserProfile> findBySearchRegex(String searchRegex, Pageable pageable);

  void deleteByUserName(String userName);

}

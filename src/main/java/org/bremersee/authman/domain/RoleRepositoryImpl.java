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

package org.bremersee.authman.domain;

import java.util.Set;
import java.util.stream.Collectors;
import javax.validation.constraints.NotNull;
import org.springframework.data.mongodb.core.MongoOperations;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * @author Christian Bremer
 */
public class RoleRepositoryImpl
    extends AbstractMongoRepositoryImpl
    implements RoleRepositoryCustom {

  public RoleRepositoryImpl(
      @NotNull MongoOperations mongoOperations) {
    super(mongoOperations);
  }

  @Override
  public Set<String> findRoleNamesByUserName(@NotNull final String userName) {
    return getMongoOperations()
        .find(
            new Query().addCriteria(Criteria.where("userName").is(userName)), Role.class)
        .stream()
        .map(Role::getRoleName)
        .collect(Collectors.toSet());
  }

  @Override
  public Set<GrantedAuthority> findGrantedAuthoritiesByUserName(@NotNull final String userName) {
    return getMongoOperations()
        .find(
            new Query().addCriteria(Criteria.where("userName").is(userName)), Role.class)
        .stream()
        .map(role -> new SimpleGrantedAuthority(role.getRoleName()))
        .collect(Collectors.toSet());
  }

}

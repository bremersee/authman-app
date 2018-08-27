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

import java.util.List;
import javax.validation.constraints.NotNull;
import lombok.extern.slf4j.Slf4j;
import org.bremersee.authman.model.OAuth2ScopeVisibility;
import org.bremersee.authman.security.core.RoleConstants;
import org.bremersee.authman.security.core.SecurityHelper;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.data.mongodb.core.MongoOperations;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.util.StringUtils;

/**
 * @author Christian Bremer
 */
@Slf4j
public class OAuth2ScopeRepositoryImpl extends AbstractMongoRepositoryImpl
    implements OAuth2ScopeRepositoryCustom {

  private static final String VISIBILITY = "visibility";

  private static Criteria searchCriteria(@NotNull final String search) {
    return Criteria.where("scope").regex("*." + search + ".*", "i");
  }

  private static Criteria userCriteria(@NotNull final String userName) {
    return new Criteria().orOperator(Criteria.where(VISIBILITY).is(OAuth2ScopeVisibility.PUBLIC),
        Criteria.where("createdBy").is(userName));
  }

  public OAuth2ScopeRepositoryImpl(
      @NotNull final MongoOperations mongoOperations) {
    super(mongoOperations);
  }

  @Override
  public boolean isVisible(String scope) {
    if (scope == null || scope.trim().length() == 0) {
      return false;
    }
    final String userName = SecurityHelper.getCurrentUserName();
    final boolean isAdmin = SecurityHelper.isCurrentUserAdmin();
    final boolean isUser = SecurityHelper.getCurrentUserRoles().contains(RoleConstants.USER_ROLE);
    if (log.isDebugEnabled()) {
      log.debug("Is oauth2 scope {} visible for user {} (is admin? {}, is user? {}) ...",
          scope, userName, isAdmin, isUser);
    }
    final Criteria scopeCriteria = Criteria.where("scope").is(scope);
    Query query = new Query();
    if (isAdmin) {
      query = query.addCriteria(scopeCriteria);
    } else if (isUser) {
      query = query.addCriteria(new Criteria().andOperator(scopeCriteria, userCriteria(userName)));
    } else {
      query = query.addCriteria(new Criteria()
          .andOperator(scopeCriteria, Criteria.where(VISIBILITY).is(OAuth2ScopeVisibility.PUBLIC)));
    }
    if (log.isDebugEnabled()) {
      log.debug("Is oauth2 scope {} visible? Using query = {}", scope, query);
    }
    return getMongoOperations().count(query, OAuth2Scope.class) > 0;
  }

  @Override
  public boolean isNotVisible(String scope) {
    return !isVisible(scope);
  }

  @Override
  public Page<OAuth2Scope> findVisibleScopes(String search, Pageable pageable) {

    Query query;
    final String userName = SecurityHelper.getCurrentUserName();
    final boolean isAdmin = SecurityHelper.isCurrentUserAdmin();
    final boolean isUser = SecurityHelper.getCurrentUserRoles().contains(RoleConstants.USER_ROLE);
    if (log.isDebugEnabled()) {
      log.debug("Looking for visible oauth2 scopes of user {} (is admin? {}, is user? {}) ...",
          userName, isAdmin, isUser);
    }
    if (isAdmin) {
      query = getAdminQuery(search);
    } else if (isUser) {
      query = getUserQuery(search, userName);
    } else {
      query = getGuestQuery(search);
    }
    if (pageable != null) {
      query.with(pageable);
    }
    if (log.isDebugEnabled()) {
      log.debug("Looking for visible oauth2 scopes, using query = {}", query);
    }
    final List<OAuth2Scope> list = getMongoOperations().find(query, OAuth2Scope.class);

    Page<OAuth2Scope> page;
    if (pageable == null) {
      page = new PageImpl<>(list);
    } else {
      long total = getMongoOperations().count(query, OAuth2Scope.class);
      page = new PageImpl<>(list, pageable, total);
    }
    return page;
  }

  private Query getAdminQuery(String search) {
    Query query = new Query();
    if (StringUtils.hasText(search)) {
      query = query.addCriteria(searchCriteria(search));
    }
    return query;
  }

  private Query getUserQuery(String search, String userName) {
    Query query = new Query();
    if (StringUtils.hasText(search)) {
      query.addCriteria(new Criteria().andOperator(searchCriteria(search), userCriteria(userName)));
    } else {
      query = query.addCriteria(userCriteria(userName));
    }
    return query;
  }

  private Query getGuestQuery(String search) {
    Query query = new Query();
    if (StringUtils.hasText(search)) {
      query = query
          .addCriteria(searchCriteria(search).and(VISIBILITY).is(OAuth2ScopeVisibility.PUBLIC));
    } else {
      query = query.addCriteria(Criteria.where(VISIBILITY).is(OAuth2ScopeVisibility.PUBLIC));
    }
    return query;
  }

}


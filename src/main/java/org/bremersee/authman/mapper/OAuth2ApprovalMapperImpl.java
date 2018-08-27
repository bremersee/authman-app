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

package org.bremersee.authman.mapper;

import java.util.Date;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Validate;
import org.bremersee.authman.domain.OAuth2Approval;
import org.springframework.security.oauth2.provider.approval.Approval;
import org.springframework.stereotype.Component;

/**
 * @author Christian Bremer
 */
@Component("oauth2ApprovalMapper")
public class OAuth2ApprovalMapperImpl implements OAuth2ApprovalMapper {

  @Override
  public Approval mapToDto(final OAuth2Approval source) {
    Validate.notNull(source, "Source must be present.");
    final Approval.ApprovalStatus status;
    if (StringUtils.isBlank(source.getStatus())) {
      status = Approval.ApprovalStatus.APPROVED;
    } else {
      status = Approval.ApprovalStatus.valueOf(source.getStatus());
    }
    return new Approval(source.getUserId(), source.getClientId(), source.getScope(),
        source.getExpiresAt(),
        status, source.getLastUpdatedAt());
  }

  @Override
  public void updateEntity(final Approval source, final OAuth2Approval destination) {
    Validate.notNull(source, "Source must be present.");
    Validate.notNull(destination, "Destination must be present.");
    destination.setUserId(source.getUserId());
    destination.setClientId(source.getClientId());
    destination.setScope(source.getScope());
    destination.setStatus(source.getStatus() == null ? Approval.ApprovalStatus.APPROVED.name() :
        source.getStatus().name());
    destination.setExpiresAt(source.getExpiresAt());
    destination.setLastUpdatedAt(
        source.getLastUpdatedAt() == null ? new Date() : source.getLastUpdatedAt());
  }
}

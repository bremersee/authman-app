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

package org.bremersee.authman.security.oauth2.provider.approval;

import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import javax.validation.constraints.NotNull;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.bremersee.authman.domain.OAuth2Approval;
import org.bremersee.authman.domain.OAuth2ApprovalRepository;
import org.bremersee.authman.mapper.OAuth2ApprovalMapper;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.oauth2.provider.approval.Approval;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;

/**
 * @author Christian Bremer
 */
@RequiredArgsConstructor
@Slf4j
public class OAuth2ApprovalStore implements ApprovalStore {

  @NonNull
  private final OAuth2ApprovalRepository repository;

  @NonNull
  private final OAuth2ApprovalMapper approvalMapper;

  @Setter
  private boolean handleRevocationsAsExpiry = false;

  @Override
  public boolean addApprovals(@NotNull final Collection<Approval> approvals) {
    for (final Approval approval : approvals) {
      OAuth2Approval entity = repository
          .findByUserIdAndClientIdAndScope(approval.getUserId(),
              approval.getClientId(), approval.getScope()).orElse(new OAuth2Approval());
      if (entity.isNew()) {
        log.debug("Adding approval {}", approval);
      } else if (log.isDebugEnabled()) {
        log.debug("Updating approval {}", approval);
      }
      approvalMapper.updateEntity(approval, entity);
      repository.save(entity);
    }
    return true;
  }

  @Override
  public boolean revokeApprovals(@NotNull final Collection<Approval> approvals) {
    long rows = 0;
    for (final Approval approval : approvals) {
      log.debug("Revoking approval {}", approval);
      if (handleRevocationsAsExpiry) {
        Optional<OAuth2Approval> optionalOAuth2Approval = repository
            .findByUserIdAndClientIdAndScope(approval.getUserId(),
                approval.getClientId(), approval.getScope());
        if (optionalOAuth2Approval.isPresent()) {
          OAuth2Approval entity = optionalOAuth2Approval.get();
          rows++;
          entity.setExpiresAt(new Date());
          repository.save(entity);
        }
      } else {
        Long row = repository.deleteByUserIdAndClientIdAndScope(approval.getUserId(),
            approval.getClientId(), approval.getScope());
        rows = rows + (row == null ? 0 : row);
      }
    }
    return rows > 0;
  }

  @Override
  public List<Approval> getApprovals(@NotNull final String userId, @NotNull final String clientId) {
    log.debug("Getting approvals with userId [{}] and clientId [{}] ...", userId, clientId);
    return repository.findByUserIdAndClientId(userId, clientId).stream()
        .map(approvalMapper::mapToDto).collect(Collectors.toList());
  }

  @Scheduled(cron = "0 2 1 * * ?") // second, minute, hour, day of month, month, day(s) of week
  public void purgeExpiredApprovals() {
    log.debug("Purging expired approvals ...");
    Long rows = repository.deleteByExpiresAtBefore(new Date());
    log.debug("Purging expired approvals ... {} deleted.", rows);
  }

}

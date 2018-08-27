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

package org.bremersee.smbcon.client;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import lombok.extern.slf4j.Slf4j;
import org.bremersee.authman.domain.UserProfileRepository;
import org.bremersee.smbcon.api.SambaConnectorControllerApi;
import org.bremersee.smbcon.model.BooleanWrapper;
import org.bremersee.smbcon.model.DnsEntry;
import org.bremersee.smbcon.model.DnsRecordRequest;
import org.bremersee.smbcon.model.DnsRecordUpdateRequest;
import org.bremersee.smbcon.model.DnsZone;
import org.bremersee.smbcon.model.DnsZoneCreateRequest;
import org.bremersee.smbcon.model.Info;
import org.bremersee.smbcon.model.Names;
import org.bremersee.smbcon.model.Password;
import org.bremersee.smbcon.model.SambaGroup;
import org.bremersee.smbcon.model.SambaGroupItem;
import org.bremersee.smbcon.model.SambaUser;
import org.bremersee.smbcon.model.SambaUserAddRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

/**
 * @author Christian Bremer
 */
@Component
@Slf4j
public class SambaConnectorFallback extends SambaConnectorMock
    implements SambaConnectorControllerApi {

  private final UserProfileRepository userProfileRepository;

  @Autowired
  public SambaConnectorFallback(UserProfileRepository userProfileRepository) {
    this.userProfileRepository = userProfileRepository;
  }

  @Override
  public ResponseEntity<SambaGroup> addGroup(@Valid final SambaGroup group) {
    log.error("Adding samba group {} failed. Running samba connector fallback.", group);
    return ResponseEntity.ok(group);
  }

  @Override
  public ResponseEntity<SambaUser> addUser(@Valid final SambaUserAddRequest sambaUser) {
    log.error("Adding samba user {} failed. Running samba connector fallback.", sambaUser);
    return ResponseEntity.ok(sambaUser);
  }

  @Override
  public ResponseEntity<Void> createDnsZone(@Valid final DnsZoneCreateRequest request) {
    log.error("Creating name server zone {} failed. Running samba connector fallback.", request);
    return ResponseEntity.ok().build();
  }

  @Override
  public ResponseEntity<Void> createOrDeleteDnsRecord(
      @NotNull @Valid final String action,
      @Valid final DnsRecordRequest request) {
    log.error("Executing '{}' with {} failed. Running samba connector fallback.", action, request);
    return ResponseEntity.ok().build();
  }

  @Override
  public ResponseEntity<Void> deleteDnsZone(@NotNull @Valid final String zoneName) {
    log.error("Deleting name server zone {} failed. Running samba connector fallback.", zoneName);
    return ResponseEntity.ok().build();
  }

  @Override
  public ResponseEntity<Void> deleteGroup(final String groupName) {
    log.error("Deleting samba group {} failed. Running samba connector fallback.", groupName);
    return ResponseEntity.ok().build();
  }

  @Override
  public ResponseEntity<Void> deleteUser(String userName) {
    log.error("Deleting samba user {} failed. Running samba connector fallback.", userName);
    return ResponseEntity.ok().build();
  }

  @Override
  public ResponseEntity<List<DnsZone>> getDnsZones() {
    log.error("Getting name server zones failed. Returning empty list.");
    return ResponseEntity.ok(new ArrayList<>());
  }

  @Override
  public ResponseEntity<List<DnsEntry>> getDnsRecords(@NotNull @Valid String zoneName) {
    log.error("Getting name server records of zone [{}] failed. Returning empty list.", zoneName);
    return ResponseEntity.ok(new ArrayList<>());
  }

  @Override
  public ResponseEntity<SambaGroup> getGroupByName(String groupName) {
    log.error("Getting samba group {} failed. Running samba connector fallback.", groupName);
    return ResponseEntity.ok(createGroup(groupName));
  }

  @Override
  public ResponseEntity<List<SambaGroupItem>> getGroups() {
    log.error("Getting samba groups failed. Running samba connector fallback.");
    return ResponseEntity.ok(Collections.emptyList());
  }

  @Override
  public ResponseEntity<BooleanWrapper> userExists(String userName) {
    log.error("The test of whether the samba user {} exists failed. "
        + "Running samba connector fallback.", userName);

    final BooleanWrapper wrapper = new BooleanWrapper();
    wrapper.setValue(false);
    userProfileRepository
        .findByUserName(userName)
        .ifPresent(
            userProfile -> wrapper.setValue(userProfile.getSambaSettings() != null));
    return ResponseEntity.ok(wrapper);
  }

  @Override
  public ResponseEntity<SambaUser> getUser(String userName) {
    log.error("Getting samba user {} failed. Running samba connector fallback.", userName);
    return ResponseEntity.ok(createUser(userName));
  }

  @Override
  public ResponseEntity<Void> updateDnsRecord(@Valid DnsRecordUpdateRequest request) {
    log.error("Updating name server with {} failed. Running samba connector fallback.", request);
    return ResponseEntity.ok().build();
  }

  @Override
  public ResponseEntity<SambaGroup> updateGroupMembers(String groupName, @Valid Names members) {
    log.error("Updating samba group {} failed. Running samba connector fallback.", groupName);
    return ResponseEntity.ok(createGroup(groupName));
  }

  @Override
  public ResponseEntity<SambaUser> updateUser(String userName, @Valid SambaUser sambaUser) {
    log.error("Updating samba user {} failed. Running samba connector fallback.", userName);
    return ResponseEntity.ok(createUser(userName));
  }

  @Override
  public ResponseEntity<SambaUser> updateUserGroups(String userName, @Valid Names groups) {
    log.error("Updating groups of user {} failed. Running samba connector fallback.", userName);
    return ResponseEntity.ok(createUser(userName));
  }

  @Override
  public ResponseEntity<Void> updateUserPassword(String userName, @Valid Password newPassword) {
    log.error("Updating password of samba user {} failed. Running samba connector fallback.",
        userName);
    return ResponseEntity.ok().build();
  }

  @Override
  public ResponseEntity<Info> getInfo() {
    return ResponseEntity.ok(
        new Info()
            .nameServerHost("ns.example.org"));
  }

}

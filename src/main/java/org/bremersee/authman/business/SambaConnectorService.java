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

import java.util.Collection;
import java.util.List;
import javax.validation.constraints.NotNull;
import org.bremersee.authman.domain.UserProfile;
import org.bremersee.smbcon.model.DnsEntry;
import org.bremersee.smbcon.model.DnsRecordType;
import org.bremersee.smbcon.model.DnsZone;
import org.bremersee.smbcon.model.Info;
import org.bremersee.smbcon.model.SambaGroup;
import org.bremersee.smbcon.model.SambaGroupItem;
import org.bremersee.smbcon.model.SambaUser;

/**
 * @author Christian Bremer
 */
public interface SambaConnectorService {

  Info getInfo();


  SambaGroup addGroup(@NotNull SambaGroup group);

  void deleteGroup(@NotNull String groupName);

  SambaGroup getGroupByName(@NotNull String groupName);

  List<SambaGroupItem> getGroups();

  SambaGroup updateGroupMembers(@NotNull String groupName, @NotNull Collection<String> members);


  void addSambaUser(@NotNull UserProfile user, @NotNull String password);

  void addSambaUserAsync(@NotNull UserProfile user, @NotNull String password);

  void updateSambaUser(@NotNull UserProfile user);

  void updateSambaUserAsync(@NotNull UserProfile user);

  void deleteUser(@NotNull String userName);

  void deleteUserAsync(@NotNull String userName);

  SambaUser getUser(@NotNull String userName);

  SambaUser updateUserGroups(@NotNull String userName, @NotNull Collection<String> groups);

  void updateUserPassword(@NotNull String userName, @NotNull String newPassword);

  void updateUserPasswordAsync(@NotNull String userName, @NotNull String newPassword);

  boolean userExists(@NotNull String userName);


  List<DnsZone> getDnsZones();

  void createDnsZone(@NotNull String zoneName);

  void deleteDnsZone(@NotNull String zoneName);

  List<DnsEntry> getDnsRecords(@NotNull String zoneName);

  void addDnsRecord(
      @NotNull String zoneName,
      @NotNull String name,
      @NotNull DnsRecordType recordType,
      @NotNull String data);

  void updateDnsRecord(
      @NotNull String zoneName,
      @NotNull String name,
      @NotNull DnsRecordType recordType,
      @NotNull String oldData,
      @NotNull String newData);

  void deleteDnsRecord(
      @NotNull String zoneName,
      @NotNull String name,
      @NotNull DnsRecordType recordType,
      @NotNull String data);

}

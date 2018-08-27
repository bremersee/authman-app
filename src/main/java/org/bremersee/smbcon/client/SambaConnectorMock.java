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

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import lombok.extern.slf4j.Slf4j;
import org.bremersee.smbcon.api.SambaConnectorControllerApi;
import org.bremersee.smbcon.model.BooleanWrapper;
import org.bremersee.smbcon.model.DnsDwDpZoneFlag;
import org.bremersee.smbcon.model.DnsEntry;
import org.bremersee.smbcon.model.DnsRecord;
import org.bremersee.smbcon.model.DnsRecordRequest;
import org.bremersee.smbcon.model.DnsRecordType;
import org.bremersee.smbcon.model.DnsRecordUpdateRequest;
import org.bremersee.smbcon.model.DnsZone;
import org.bremersee.smbcon.model.DnsZoneCreateRequest;
import org.bremersee.smbcon.model.DnsZoneFlag;
import org.bremersee.smbcon.model.Info;
import org.bremersee.smbcon.model.Names;
import org.bremersee.smbcon.model.Password;
import org.bremersee.smbcon.model.SambaGroup;
import org.bremersee.smbcon.model.SambaGroupItem;
import org.bremersee.smbcon.model.SambaUser;
import org.bremersee.smbcon.model.SambaUserAddRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;

/**
 * @author Christian Bremer
 */
@Slf4j
public class SambaConnectorMock implements SambaConnectorControllerApi {

  private static final String ZONE_MSDCS = "_msdcs.eixe.bremersee.org";

  private static final String ZONE_MY = "eixe.bremersee.org";

  private static final String ZONE_MY_REVERSE = "1.168.192.in-addr.arpa";

  private final Map<DnsZone, List<DnsEntry>> ns = new ConcurrentHashMap<>();

  public SambaConnectorMock() {
    createDnsZones().forEach(dnsZone -> ns.put(dnsZone, new ArrayList<>()));

    createOrDeleteDnsRecord(
        "CREATE", // NOSONAR
        new DnsRecordRequest()
            .zoneName(ZONE_MSDCS)
            .name("").recordType(DnsRecordType.SOA)
            .data("serial=1, refresh=900, retry=600, expire=86400, minttl=3600, "
                + "ns=dc.eixe.bremersee.org., email=hostmaster.eixe.bremersee.org."));
    createOrDeleteDnsRecord(
        "CREATE", // NOSONAR
        new DnsRecordRequest()
            .zoneName(ZONE_MSDCS)
            .name("").recordType(DnsRecordType.NS)
            .data("dc.eixe.bremersee.org."));

    createOrDeleteDnsRecord(
        "CREATE", // NOSONAR
        new DnsRecordRequest()
            .zoneName(ZONE_MY)
            .name("vmhost").recordType(DnsRecordType.A)
            .data("192.168.1.7")); // NOSONAR
    createOrDeleteDnsRecord(
        "CREATE",
        new DnsRecordRequest()
            .zoneName(ZONE_MY_REVERSE)
            .name("7").recordType(DnsRecordType.PTR)
            .data("vmhost.eixe.bremersee.org")); // NOSONAR

    createOrDeleteDnsRecord(
        "CREATE", // NOSONAR
        new DnsRecordRequest()
            .zoneName(ZONE_MY)
            .name("zander").recordType(DnsRecordType.A)
            .data("192.168.1.200")); // NOSONAR
    createOrDeleteDnsRecord(
        "CREATE",
        new DnsRecordRequest()
            .zoneName(ZONE_MY_REVERSE)
            .name("200").recordType(DnsRecordType.PTR)
            .data("zander.eixe.bremersee.org")); // NOSONAR
  }

  private List<DnsZone> createDnsZones() {
    final List<DnsZone> zones = new ArrayList<>();
    zones.add(createDnsZone(ZONE_MY_REVERSE));
    zones.add(createDnsZone(ZONE_MY));
    zones.add(createDnsZone(ZONE_MSDCS));
    return zones;
  }

  private DnsZone createDnsZone(@NotNull final String name) {
    return createDnsZone(
        name, null, null, null, null, null);
  }

  @SuppressWarnings("SameParameterValue")
  private DnsZone createDnsZone(
      @NotNull final String name,
      final String[] flags,
      final String zoneType,
      final String version,
      final String[] dwDpFlags,
      final String pszDpFqdn) {

    final DnsZone zone = new DnsZone();
    zone.setPszZoneName(name);
    if (flags != null && flags.length > 0) {
      zone.setFlags(
          Arrays.stream(flags).map(this::createDnsZoneFlag).collect(Collectors.toList()));
    } else {
      zone.addFlagsItem(new DnsZoneFlag().name("DNS_RPC_ZONE_DSINTEGRATED"));
      zone.addFlagsItem(new DnsZoneFlag().name("DNS_RPC_ZONE_UPDATE_SECURE"));
    }
    zone.setZoneType(StringUtils.hasText(zoneType) ? zoneType : "DNS_ZONE_TYPE_PRIMARY");
    zone.setVersion(StringUtils.hasText(version) ? version : "50");
    if (dwDpFlags != null && dwDpFlags.length > 0) {
      zone.setDwDpFlags(
          Arrays.stream(dwDpFlags).map(this::createDnsDwDpZoneFlag).collect(Collectors.toList()));
    } else {
      zone.addDwDpFlagsItem(new DnsDwDpZoneFlag().name("DNS_DP_AUTOCREATED"));
      zone.addDwDpFlagsItem(new DnsDwDpZoneFlag().name("DNS_DP_DOMAIN_DEFAULT"));
      zone.addDwDpFlagsItem(new DnsDwDpZoneFlag().name("DNS_DP_ENLISTED"));
    }
    final String defaultPsz = name.startsWith("_msdcs")
        ? "ForestDnsZones.eixe.bremersee.org"
        : "DomainDnsZones.eixe.bremersee.org";
    zone.setPszDpFqdn(StringUtils.hasText(pszDpFqdn) ? pszDpFqdn : defaultPsz);
    return zone;
  }

  private DnsZoneFlag createDnsZoneFlag(String name) {
    return new DnsZoneFlag().name(name);
  }

  private DnsDwDpZoneFlag createDnsDwDpZoneFlag(String name) {
    return new DnsDwDpZoneFlag().name(name);
  }

  SambaGroup createGroup(String name) {
    final SambaGroup group = new SambaGroup();
    group.setCreated(OffsetDateTime.now());
    group.setDistinguishedName("cn=" + name);
    group.setMembers(new ArrayList<>());
    group.setModified(OffsetDateTime.now());
    group.setName(name);
    return group;
  }

  SambaUser createUser(String name) {
    final SambaUser user = new SambaUser();
    user.setCreated(OffsetDateTime.now());
    user.setDistinguishedName("cn=" + name);
    user.setModified(OffsetDateTime.now());
    user.setDisplayName("Samba User");
    user.setEmail("samba@example.org");
    user.setEnabled(true);
    user.setGroups(new ArrayList<>());
    user.setMobile("012345678901");
    user.setUserName(name);
    return user;
  }

  @Override
  public ResponseEntity<SambaGroup> addGroup(@Valid final SambaGroup group) {
    log.info("Samba connector MOCK is adding samba group {}", group);
    return ResponseEntity.ok(group);
  }

  @Override
  public ResponseEntity<SambaUser> addUser(@Valid final SambaUserAddRequest sambaUser) {
    log.info("Samba connector MOCK is adding samba user {}", sambaUser);
    return ResponseEntity.ok(sambaUser);
  }

  @Override
  public ResponseEntity<Void> createDnsZone(@Valid final DnsZoneCreateRequest request) {
    log.info("Samba connector MOCK is creating name server zone {}", request);
    final String name = request.getPszZoneName();
    final DnsZone zone = createDnsZone(name);
    ns.computeIfAbsent(zone, k -> new ArrayList<>());
    return ResponseEntity.ok().build();
  }

  @Override
  public ResponseEntity<Void> createOrDeleteDnsRecord( // NOSONAR
      @NotNull @Valid final String action,
      @Valid final DnsRecordRequest request) {
    log.info("Samba connector MOCK is executing '{}' with {}", action, request);
    final List<DnsEntry> entries = ns.get(createDnsZone(request.getZoneName()));
    if (entries != null) {
      if ("DELETE".equals(action)) {
        entries.forEach(dnsEntry -> {
          if (dnsEntry.getRecords() != null
              && String.valueOf(dnsEntry.getName()).equals(request.getName())) {
            dnsEntry.getRecords().removeIf(
                dnsRecord -> String.valueOf(dnsRecord.getRecordValue()).equals(request.getData())
                    && String.valueOf(request.getRecordType()).equals(dnsRecord.getRecordType()));
          }
        });
        entries.removeIf(
            dnsEntry -> dnsEntry.getRecords() == null || dnsEntry.getRecords().isEmpty());
      } else if ("CREATE".equals(action)) {
        final DnsRecord record = new DnsRecord()
            .recordType(String.valueOf(request.getRecordType()))
            .recordValue(request.getData())
            .flags("f0")
            .serial("2417")
            .ttl("3600");
        boolean added = false;
        for (DnsEntry dnsEntry : entries) {
          if (String.valueOf(dnsEntry.getName()).equals(request.getName())) {
            dnsEntry.addRecordsItem(record);
            added = true;
            break;
          }
        }
        if (!added) {
          entries.add(new DnsEntry()
              .name(request.getName())
              .addRecordsItem(record));
        }
      } else {
        log.warn("Action {} is not supported. Doing nothing.");
      }
    }
    return ResponseEntity.ok().build();
  }

  @Override
  public ResponseEntity<Void> deleteDnsZone(@NotNull @Valid final String zoneName) {
    log.info("Samba connector MOCK is deleting name server zone {}", zoneName);
    ns.remove(createDnsZone(zoneName));
    return ResponseEntity.ok().build();
  }

  @Override
  public ResponseEntity<Void> deleteGroup(String groupName) {
    log.info("Samba connector MOCK is deleting samba group {}", groupName);
    return ResponseEntity.ok().build();
  }

  @Override
  public ResponseEntity<Void> deleteUser(String userName) {
    log.info("Samba connector MOCK is deleting samba user {}", userName);
    return ResponseEntity.ok().build();
  }

  @Override
  public ResponseEntity<List<DnsZone>> getDnsZones() {
    log.info("Samba connector MOCK is getting name server zones.");
    return ResponseEntity.ok(new ArrayList<>(ns.keySet()));
  }

  @Override
  public ResponseEntity<List<DnsEntry>> getDnsRecords(@NotNull @Valid String zoneName) {
    log.info("Samba connector MOCK is getting name server records of zone {}", zoneName);
    final List<DnsEntry> entries = ns.get(createDnsZone(zoneName));
    log.debug("Samba connector MOCK is getting name server records of zone {}: {}", zoneName,
        entries);
    return ResponseEntity.ok(entries == null ? new ArrayList<>() : new ArrayList<>(entries));
  }

  @Override
  public ResponseEntity<SambaGroup> getGroupByName(String groupName) {
    log.info("Samba connector MOCK is getting samba group {}", groupName);
    return ResponseEntity.ok(createGroup(groupName));
  }

  @Override
  public ResponseEntity<List<SambaGroupItem>> getGroups() {
    log.info("Samba connector MOCK is getting samba groups.");
    return ResponseEntity.ok(Collections.singletonList(createGroup("Administrators")));
  }

  @Override
  public ResponseEntity<Info> getInfo() {
    return ResponseEntity.ok(
        new Info()
            .nameServerHost("ns.example.org"));
  }

  public ResponseEntity<BooleanWrapper> userExists(String userName) {
    log.info("Samba connector MOCK is getting samba user {} exists?", userName);
    final BooleanWrapper wrapper = new BooleanWrapper();
    wrapper.setValue(true);
    return ResponseEntity.ok(wrapper);
  }

  @Override
  public ResponseEntity<SambaUser> getUser(String userName) {
    log.info("Samba connector MOCK is getting samba user {}", userName);
    return ResponseEntity.ok(createUser(userName));
  }

  @Override
  public ResponseEntity<Void> updateDnsRecord(@Valid DnsRecordUpdateRequest request) {
    log.info("Samba connector MOCK updates dns record {}", request);
    final List<DnsEntry> entries = ns.get(createDnsZone(request.getZoneName()));
    if (entries != null) {
      entries.forEach(dnsEntry -> {
        if (dnsEntry.getRecords() != null
            && String.valueOf(dnsEntry.getName()).equals(request.getName())) {
          dnsEntry.getRecords().forEach(dnsRecord -> {
            if (String.valueOf(request.getRecordType()).equals(dnsRecord.getRecordType())
                && String.valueOf(request.getOldData()).equals(dnsRecord.getRecordValue())) {
              dnsRecord.setRecordValue(request.getNewData());
            }
          });
        }
      });
    }
    return ResponseEntity.ok().build();
  }

  @Override
  public ResponseEntity<SambaGroup> updateGroupMembers(String groupName, @Valid Names members) {
    log.info("Samba connector MOCK is updating samba group {} members: {}", groupName, members);
    return ResponseEntity.ok(createGroup(groupName));
  }

  @Override
  public ResponseEntity<SambaUser> updateUser(String userName, @Valid SambaUser sambaUser) {
    log.info("Samba connector MOCK is updating samba user {}", userName);
    return ResponseEntity.ok(createUser(userName));
  }

  @Override
  public ResponseEntity<SambaUser> updateUserGroups(String userName, @Valid Names groups) {
    log.info("Samba connector MOCK is updating samba user {} groups: {}", userName, groups);
    return ResponseEntity.ok(createUser(userName));
  }

  @Override
  public ResponseEntity<Void> updateUserPassword(String userName, @Valid Password newPassword) {
    log.info("Samba connector MOCK is setting new samba user {} password.", userName);
    return ResponseEntity.ok().build();
  }
}

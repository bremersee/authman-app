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

package org.bremersee.authman.controller.nameserver;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.bremersee.smbcon.model.DnsEntry;
import org.bremersee.smbcon.model.DnsRecord;
import org.bremersee.smbcon.model.DnsZone;

/**
 * @author Christian Bremer
 */
@Getter
@Setter
@NoArgsConstructor
@EqualsAndHashCode
@ToString
public class NameServerEntry implements Serializable, Comparable<NameServerEntry> {

  private DnsZone zone;

  private List<NameServerZoneEntry> entries;

  public NameServerEntry(
      final DnsZone zone,
      final List<DnsEntry> dnsEntries) {

    this.zone = zone;
    this.entries = new ArrayList<>();
    if (dnsEntries != null && !dnsEntries.isEmpty()) {
      for (final DnsEntry dnsEntry : dnsEntries) {
        if (dnsEntry.getRecords() == null || dnsEntry.getRecords().isEmpty()) {
          final NameServerZoneEntry zoneEntry = new NameServerZoneEntry();
          zoneEntry.setName(dnsEntry.getName());
          this.entries.add(zoneEntry);
        } else {
          for (final DnsRecord dnsRecord : dnsEntry.getRecords()) {
            final NameServerZoneEntry zoneEntry = new NameServerZoneEntry();
            zoneEntry.setName(dnsEntry.getName());
            zoneEntry.setRecordType(dnsRecord.getRecordType());
            zoneEntry.setRecordValue(dnsRecord.getRecordValue());
            zoneEntry.setFlags(dnsRecord.getFlags());
            zoneEntry.setSerial(dnsRecord.getSerial());
            zoneEntry.setTtl(dnsRecord.getTtl());
            this.entries.add(zoneEntry);
          }
        }
      }
      Collections.sort(this.entries);
    }
  }

  @Override
  public int compareTo(NameServerEntry o) {
    String s0 = zone != null && zone.getPszZoneName() != null ? zone.getPszZoneName() : "";
    String s1 = o != null && o.getZone() != null && o.getZone().getPszZoneName() != null
        ? o.getZone().getPszZoneName()
        : "";
    if (s0.toLowerCase().startsWith("_msdcs.")) {
      return 1;
    } else if (s1.toLowerCase().startsWith("_msdcs.")) {
      return -1;
    }
    return s0.compareToIgnoreCase(s1);
  }
}

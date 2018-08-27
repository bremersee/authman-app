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
import java.util.regex.Pattern;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.bremersee.smbcon.model.DnsEntry;
import org.bremersee.smbcon.model.DnsRecord;

/**
 * @author Christian Bremer
 */
@Getter
@Setter
@NoArgsConstructor
@ToString
@EqualsAndHashCode
public class NameServerZoneEntry implements Serializable, Comparable<NameServerZoneEntry> {

  private static final long serialVersionUID = 4639914425880099621L;

  private String name = null;

  private String recordType = null;

  private String recordValue = null;

  private String flags = null;

  private String serial = null;

  private String ttl = null;

  public NameServerZoneEntry(DnsEntry dnsEntry, DnsRecord dnsRecord) {
    this(dnsEntry != null ? dnsEntry.getName() : null, dnsRecord);
  }

  public NameServerZoneEntry(String name, DnsRecord dnsRecord) {
    this.name = name;
    if (dnsRecord != null) {
      this.recordType = dnsRecord.getRecordType();
      this.recordValue = dnsRecord.getRecordValue();
      this.flags = dnsRecord.getFlags();
      this.serial = dnsRecord.getSerial();
      this.ttl = dnsRecord.getTtl();
    }
  }

  @SuppressWarnings("NullableProblems")
  @Override
  public int compareTo(NameServerZoneEntry o) {
    final String n0 = name != null ? name : "";
    final String n1 = o != null && o.getName() != null ? o.getName() : "";
    return compare(n0, n1);
  }

  private int compare(String a, String b) {
    final String[] aa = a.split(Pattern.quote("."));
    final String[] bb = b.split(Pattern.quote("."));
    if (aa.length > 1 && aa.length == bb.length) {
      for (int i = 0; i < aa.length; i++) {
        final int c = compare(aa[i], bb[i]);
        if (c != 0) {
          return c;
        }
      }
      return 0;
    }

    try {
      int n0 = Integer.parseInt(a);
      int n1 = Integer.parseInt(b);
      return Integer.compare(n0, n1);

    } catch (RuntimeException re) {
      return a.compareToIgnoreCase(b);
    }
  }

}

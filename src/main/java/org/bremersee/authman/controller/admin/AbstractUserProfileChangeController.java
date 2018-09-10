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

package org.bremersee.authman.controller.admin;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.bremersee.authman.business.SambaConnectorService;
import org.bremersee.authman.controller.AbstractController;
import org.bremersee.authman.model.SelectOptionDto;
import org.bremersee.smbcon.model.SambaGroupItem;
import org.springframework.web.servlet.LocaleResolver;

/**
 * @author Christian Bremer
 */
@Slf4j
public class AbstractUserProfileChangeController extends AbstractController {

  private static final Object SAMBA_GROUPS_LOCK = new Object();

  private static long getSambaGroupsTime;

  private static List<SelectOptionDto> sambaGroups;

  private final SambaConnectorService sambaConnector;

  public AbstractUserProfileChangeController(
      final SambaConnectorService sambaConnectorService,
      final LocaleResolver localeResolver) {
    super(localeResolver);
    this.sambaConnector = sambaConnectorService;
  }

  protected List<SelectOptionDto> sambaGroups() {
    return sambaGroups(sambaConnector);
  }

  private static List<SelectOptionDto> sambaGroups(SambaConnectorService sambaConnector) {
    synchronized (SAMBA_GROUPS_LOCK) {
      if (sambaGroups == null || Math.abs(System.currentTimeMillis() - getSambaGroupsTime) > 3333) {
        final List<SambaGroupItem> groups = sambaConnector.getGroups();
        if (groups == null) {
          return Collections.emptyList();
        }
        sambaGroups = groups
            .stream()
            .map(sambaGroupItem -> new SelectOptionDto(
                urlEncode(normalizeDistinguishedName(sambaGroupItem.getDistinguishedName())),
                sambaGroupItem.getName(),
                false))
            .collect(Collectors.toList());
        getSambaGroupsTime = System.currentTimeMillis();
      }
      return sambaGroups;
    }
  }

}

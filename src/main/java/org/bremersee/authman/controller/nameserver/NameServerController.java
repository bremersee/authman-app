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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.bremersee.authman.business.SambaConnectorService;
import org.bremersee.authman.controller.AbstractController;
import org.bremersee.authman.controller.RedirectMessage;
import org.bremersee.authman.controller.RedirectMessageType;
import org.bremersee.authman.model.SelectOptionDto;
import org.bremersee.smbcon.model.DnsRecordType;
import org.bremersee.smbcon.model.DnsZoneCreateRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * @author Christian Bremer
 */
@Controller
@Slf4j
public class NameServerController extends AbstractController {

  private final SambaConnectorService sambaConnectorService;

  @Autowired
  public NameServerController(
      final LocaleResolver localeResolver,
      final SambaConnectorService sambaConnectorService) {
    super(localeResolver);
    this.sambaConnectorService = sambaConnectorService;
  }

  @ModelAttribute("nameServerHost")
  public String nameServerHost() {
    return sambaConnectorService.getInfo().getNameServerHost();
  }

  @ModelAttribute("dnsRecordTypes")
  public List<SelectOptionDto> dnsRecordTypes() {
    final List<SelectOptionDto> dnsRecordTypes = new ArrayList<>();
    for (final DnsRecordType rt : DnsRecordType.values()) {
      dnsRecordTypes.add(new SelectOptionDto(rt.name(), rt.name(), false));
    }
    return dnsRecordTypes;
  }

  @GetMapping(path = "/admin/ns/records")
  public String displayZonesView(final ModelMap model) {

    if (!model.containsAttribute("entries")) {
      final List<NameServerEntry> entries = new ArrayList<>();
      sambaConnectorService.getDnsZones().forEach(
          dnsZone -> entries.add(
              new NameServerEntry(
                  dnsZone,
                  sambaConnectorService.getDnsRecords(dnsZone.getPszZoneName()))));
      Collections.sort(entries);
      model.addAttribute("entries", entries);
    }
    if (!model.containsAttribute("newZone")) {
      model.addAttribute("newZone", new DnsZoneCreateRequest());
    }
    if (!model.containsAttribute("newRecord")) {
      model.addAttribute("newRecord", new NameServerZoneEntryAddCommand());
    }
    return "admin/ns/records";
  }

  @PostMapping(path = "/admin/ns/add-zone")
  public String addZone(
      @ModelAttribute("zone") final DnsZoneCreateRequest cmd,
      final ModelMap model,
      final HttpServletRequest request,
      final RedirectAttributes redirectAttributes) {

    log.info("Adding zone {}", cmd);

    if (StringUtils.hasText(cmd.getPszZoneName())) {
      sambaConnectorService.createDnsZone(cmd.getPszZoneName());

      model.clear();
      final String msg = getMessageSource().getMessage(
          "i18n.ns.zone.created",
          new Object[]{cmd.getPszZoneName()},
          resolveLocale(request));
      final RedirectMessage rmsg = new RedirectMessage(msg, RedirectMessageType.SUCCESS);
      redirectAttributes.addFlashAttribute(RedirectMessage.ATTRIBUTE_NAME, rmsg);
      log.info("Zone [{}] was added.", cmd);
    }
    return "redirect:/admin/ns/records"; // NOSONAR
  }

  @PostMapping(path = "/admin/ns/delete-zone")
  public String deleteZone(
      @RequestParam("zoneName") final String zoneName,
      final ModelMap model,
      final HttpServletRequest request,
      final RedirectAttributes redirectAttributes) {

    log.info("Deleting zone {}", zoneName);

    if (StringUtils.hasText(zoneName)) {
      sambaConnectorService.deleteDnsZone(zoneName);

      model.clear();
      final String msg = getMessageSource().getMessage(
          "i18n.ns.zone.deleted",
          new Object[]{zoneName},
          resolveLocale(request));
      final RedirectMessage rmsg = new RedirectMessage(msg, RedirectMessageType.SUCCESS);
      redirectAttributes.addFlashAttribute(RedirectMessage.ATTRIBUTE_NAME, rmsg);
      log.info("Zone [{}] was deleted.", zoneName);
    }
    return "redirect:/admin/ns/records";
  }

  @PostMapping(path = "/admin/ns/add-record")
  public String addRecord(
      @RequestParam(name = "zoneName") final String zoneName,
      @ModelAttribute("newRecord") final NameServerZoneEntryAddCommand cmd,
      final ModelMap model,
      final HttpServletRequest request,
      final RedirectAttributes redirectAttributes) {

    final String name = cmd.getName();
    final String recordType = cmd.getRecordType();
    final String recordValue = cmd.getRecordValue();

    log.info("Adding dns record {} {} {} in zone {}", name, recordType, recordValue, zoneName);

    final DnsRecordType dnsRecordType =
        StringUtils.hasText(recordType) ? DnsRecordType.fromValue(recordType) : null;
    if (StringUtils.hasText(name) && dnsRecordType != null && StringUtils.hasText(recordValue)) {
      sambaConnectorService.addDnsRecord(
          zoneName,
          name,
          dnsRecordType,
          recordValue);

      model.clear();
      final String msg = getMessageSource().getMessage(
          "i18n.ns.record.created",
          new Object[]{name + " " + recordType + " " + recordValue},
          resolveLocale(request));
      final RedirectMessage rmsg = new RedirectMessage(msg, RedirectMessageType.SUCCESS);
      redirectAttributes.addFlashAttribute(RedirectMessage.ATTRIBUTE_NAME, rmsg);
      log.info("Record [{} {} {}] was added to zone {}.", name, recordType, recordValue, zoneName);
    }

    return "redirect:/admin/ns/records";
  }

  @PostMapping(path = "/admin/ns/delete-record")
  public String deleteRecord(
      @RequestParam("zoneName") final String zoneName,
      @RequestParam("name") final String name,
      @RequestParam("recordType") final String recordType,
      @RequestParam("data") final String data,
      final ModelMap model,
      final HttpServletRequest request,
      final RedirectAttributes redirectAttributes) {

    log.info("Deleting dns record {} {} {} from {}", name, recordType, data, zoneName);

    final DnsRecordType dnsRecordType = DnsRecordType.fromValue(recordType);
    if (StringUtils.hasText(zoneName) && StringUtils.hasText(name) && dnsRecordType != null
        && StringUtils.hasText(data)) {
      sambaConnectorService.deleteDnsRecord(
          zoneName,
          name,
          dnsRecordType,
          data);

      model.clear();
      final String msg = getMessageSource().getMessage(
          "i18n.ns.record.deleted",
          new Object[]{name + " " + recordType + " " + data},
          resolveLocale(request));
      final RedirectMessage rmsg = new RedirectMessage(msg, RedirectMessageType.SUCCESS);
      redirectAttributes.addFlashAttribute(RedirectMessage.ATTRIBUTE_NAME, rmsg);
      log.info("Zone [{} {} {}] was deleted.", name, recordType, data);
    }
    return "redirect:/admin/ns/records";
  }

  @GetMapping(path = "/admin/ns/update-record")
  public String displayUpdateRecordView(
      @RequestParam("zoneName") final String zoneName,
      @RequestParam("name") final String name,
      @RequestParam("recordType") final String recordType,
      @RequestParam("data") final String data,
      final ModelMap model) {

    if (!model.containsAttribute("zoneName")) {
      model.addAttribute("zoneName", zoneName);
    }
    if (!model.containsAttribute("record")) {
      model.addAttribute(
          "record",
          new NameServerRecordUpdateCommand(name, recordType, data, data));
    }
    return "admin/ns/update-record";
  }

  @PostMapping(path = "/admin/ns/update-record")
  public String updateRecord(
      @RequestParam("zoneName") final String zoneName,
      @ModelAttribute("record") final NameServerRecordUpdateCommand cmd,
      final ModelMap model,
      final HttpServletRequest request,
      final RedirectAttributes redirectAttributes) {

    log.info("Updating dns record {} of zone {}", cmd, zoneName);

    final DnsRecordType dnsRecordType = StringUtils.hasText(cmd.getRecordType())
        ? DnsRecordType.fromValue(cmd.getRecordType())
        : null;
    if (StringUtils.hasText(zoneName)
        && StringUtils.hasText(cmd.getName())
        && dnsRecordType != null
        && StringUtils.hasText(cmd.getRecordValue())
        && StringUtils.hasText(cmd.getNewRecordValue())) {

      sambaConnectorService.updateDnsRecord(
          zoneName,
          cmd.getName(),
          dnsRecordType,
          cmd.getRecordValue(),
          cmd.getNewRecordValue());

      model.clear();
      final String msg = getMessageSource().getMessage(
          "i18n.ns.record.updated",
          new Object[]{cmd.getName() + " " + cmd.getRecordType() + " " + cmd.getNewRecordValue()},
          resolveLocale(request));
      final RedirectMessage rmsg = new RedirectMessage(msg, RedirectMessageType.SUCCESS);
      redirectAttributes.addFlashAttribute(RedirectMessage.ATTRIBUTE_NAME, rmsg);
      log.info("Zone [{}] was updated.", cmd);
    } else {
      model.clear();
    }
    return "redirect:/admin/ns/records";
  }

}

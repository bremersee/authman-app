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

package org.bremersee.authman.controller.developer;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.bremersee.authman.business.OAuth2ClientService;
import org.bremersee.authman.business.PostmanCollectionService;
import org.bremersee.authman.controller.AbstractController;
import org.bremersee.authman.controller.RedirectMessage;
import org.bremersee.authman.controller.RedirectMessageType;
import org.bremersee.authman.model.OAuth2ClientDto;
import org.bremersee.authman.model.postman.Collection;
import org.bremersee.authman.security.core.SecurityHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * @author Christian Bremer
 */
@Controller
@Slf4j
public class OAuth2ClientsController extends AbstractController {

  private final OAuth2ClientService clientService;

  private final PostmanCollectionService postmanCollectionService;

  private ObjectMapper objectMapper = new ObjectMapper();

  @Autowired
  public OAuth2ClientsController(
      final OAuth2ClientService clientService,
      final PostmanCollectionService postmanCollectionService,
      final LocaleResolver localeResolver) {
    super(localeResolver);
    this.clientService = clientService;
    this.postmanCollectionService = postmanCollectionService;
  }

  @Autowired(required = false)
  public void setObjectMapper(final ObjectMapper objectMapper) {
    if (objectMapper != null) {
      this.objectMapper = objectMapper;
    }
  }

  @GetMapping(path = "/developer/clients")
  public String displayClients(
      @RequestParam(name = "q", required = false) String search,
      Pageable pageable,
      ModelMap model) {

    log.info("Displaying clients with search = {} and pageable = {}", search, pageable);

    if (!model.containsAttribute("clientPage")) {
      Page<OAuth2ClientDto> clientPage = clientService.getClients(search, pageable);
      model.addAttribute("clientPage", clientPage);
    }

    return "developer/clients";
  }

  @PostMapping(path = "/developer/clients", params = {"id"})
  public String deleteClient(
      @RequestParam("id") String clientId,
      ModelMap model,
      HttpServletRequest request,
      RedirectAttributes redirectAttributes) {

    clientService.deleteClient(clientId);

    model.clear();
    final String msg = getMessageSource().getMessage(
        "oauth2.client.deleted",
        new Object[]{clientId},
        resolveLocale(request));
    final RedirectMessage rmsg = new RedirectMessage(msg, RedirectMessageType.SUCCESS);
    redirectAttributes.addFlashAttribute(RedirectMessage.ATTRIBUTE_NAME, rmsg);
    log.info("User [{}] has successfully deleted client [{}].",
        SecurityHelper.getCurrentUserName(), clientId);
    return "redirect:/developer/clients";
  }

  @GetMapping(path = "/developer/clients/postman")
  public void downloadPostmanCollection(
      @RequestParam("id") String clientId,
      HttpServletRequest request,
      HttpServletResponse response) throws IOException {

    final String scheme = request.getScheme();
    final String host = request.getServerName();
    final int port = request.getServerPort();
    final Collection postmanCollection = postmanCollectionService.generatePostmanCollection(
        clientId, scheme, host, port);
    byte[] jsonBytes = objectMapper
        .writerWithDefaultPrettyPrinter().writeValueAsBytes(postmanCollection);
    response.setContentType("application/json");
    response.setHeader("Content-Disposition",
        "attachment; filename=\"" + clientId +".postman_collection.json\""); // inline
    response.setContentLength(jsonBytes.length);
    response.getOutputStream().write(jsonBytes);
    response.getOutputStream().flush();
  }
}

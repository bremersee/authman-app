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

import javax.servlet.http.HttpServletRequest;
import javax.validation.constraints.NotNull;
import lombok.extern.slf4j.Slf4j;
import org.bremersee.authman.business.UserProfileService;
import org.bremersee.authman.controller.AbstractController;
import org.bremersee.authman.controller.RedirectMessage;
import org.bremersee.authman.controller.RedirectMessageType;
import org.bremersee.authman.model.UserProfileDto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * @author Christian Bremer
 */
@Controller
@RequestMapping(path = "/admin/users")
@Slf4j
public class UserProfilesController extends AbstractController {

  private final UserProfileService userProfileService;

  @Autowired
  public UserProfilesController(
      final UserProfileService userProfileService,
      @NotNull LocaleResolver localeResolver) {
    super(localeResolver);
    this.userProfileService = userProfileService;
  }

  @GetMapping
  public String displayUsersView(
      @RequestParam(name = "q", required = false) final String search,
      final Pageable pageable,
      final ModelMap model) {

    log.info("Displaying users with search = {} and pageable = {}", search, pageable);

    if (!model.containsAttribute("userPage")) {
      final Page<UserProfileDto> userPage = userProfileService.getUserProfiles(search, pageable);
      model.addAttribute("userPage", userPage);
    }

    return "admin/users";
  }

  @PostMapping(params = {"user"})
  public String deleteUser(
      @RequestParam("user") final String userName,
      final ModelMap model,
      final HttpServletRequest request,
      final RedirectAttributes redirectAttributes) {

    userProfileService.deleteUserProfile(userName);

    model.clear();
    final String msg = getMessageSource().getMessage(
        "i18n.user.deleted",
        new Object[]{userName},
        resolveLocale(request));
    final RedirectMessage rmsg = new RedirectMessage(msg, RedirectMessageType.SUCCESS);
    redirectAttributes.addFlashAttribute(RedirectMessage.ATTRIBUTE_NAME, rmsg);
    log.info("User [{}] was successfully deleted.", userName);
    return "redirect:/admin/users";
  }
}

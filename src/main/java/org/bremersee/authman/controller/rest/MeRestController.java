/*
 * Copyright 2015 the original author or authors.
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

package org.bremersee.authman.controller.rest;

import java.security.Principal;
import lombok.extern.slf4j.Slf4j;
import org.bremersee.authman.business.UserProfileService;
import org.bremersee.authman.model.UserProfileDto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Christian Bremer
 */
@RestController
@RequestMapping(path = "/api/me")
@Slf4j
public class MeRestController {

  private final UserProfileService userProfileService;

  @Autowired
  public MeRestController(UserProfileService userProfileService) {
    this.userProfileService = userProfileService;
  }

  @PreAuthorize("hasRole('ROLE_USER')")
  @RequestMapping(
      method = RequestMethod.GET,
      produces = {MediaType.APPLICATION_JSON_VALUE})
  public UserProfileDto me(Principal me) {
    UserProfileDto userProfile = userProfileService.getUserProfile(me.getName());
    log.debug("Returning me: {}", userProfile);
    return userProfile;
  }

}

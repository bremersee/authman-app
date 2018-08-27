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

package org.bremersee.authman.controller;

import lombok.extern.slf4j.Slf4j;
import org.bremersee.authman.model.UserProfileCreateRequestDto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.LocaleResolver;

/**
 * @author Christian Bremer
 */
@Controller("userRegistrationSuccessController")
@RequestMapping("/registered")
@Slf4j
public class UserRegistrationSuccessController extends AbstractController {

  @Autowired
  public UserRegistrationSuccessController(
      final LocaleResolver localeResolver) {
    super(localeResolver);
  }

  @RequestMapping(method = RequestMethod.GET)
  public String displayRegisteredView(
      @ModelAttribute(value = "registered", binding = false) UserProfileCreateRequestDto registered,
      SessionStatus sessionStatus) {

    sessionStatus.setComplete();
    if (registered == null) {
      log.warn("There's no registration - redirecting to '/register'");
      return "redirect:/register";
    }
    return "registered";
  }

}

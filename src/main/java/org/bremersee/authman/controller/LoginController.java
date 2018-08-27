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

import javax.validation.constraints.NotNull;
import lombok.extern.slf4j.Slf4j;
import org.bremersee.authman.validation.ValidationProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.LocaleResolver;

/**
 * @author Christian Bremer
 */
@Controller("loginController")
@EnableConfigurationProperties(ValidationProperties.class)
@Slf4j
public class LoginController extends AbstractController {

  private final ValidationProperties validationProperties;

  @Autowired
  public LoginController(
      @NotNull final ValidationProperties validationProperties,
      @NotNull final LocaleResolver localeResolver) {

    super(localeResolver);
    this.validationProperties = validationProperties;
  }

  @RequestMapping(
      path = "/login",
      method = RequestMethod.GET)
  public String displayLoginView(Model model) {

    if (!model.containsAttribute("userNamePattern")) {
      model.addAttribute("userNamePattern",
          validationProperties.getUserNamePattern().pattern());
    }

    return "login";
  }

}

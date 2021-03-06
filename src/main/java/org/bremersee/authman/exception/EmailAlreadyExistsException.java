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

package org.bremersee.authman.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * @author Christian Bremer
 */
@ResponseStatus(code = HttpStatus.NOT_ACCEPTABLE, reason = "Email address already exists.")
public class EmailAlreadyExistsException extends IllegalArgumentException {

  @Getter
  private final String email;

  public EmailAlreadyExistsException(String email) {
    super(email + " already exists.");
    this.email = email;
  }
}

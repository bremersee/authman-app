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

package org.bremersee.authman.model.postman;

import java.util.List;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

/**
 * @author Christian Bremer
 */
@Getter
@Setter
@ToString
@EqualsAndHashCode
@NoArgsConstructor
public class Auth {

  public static final String TYPE_NOAUTH = "noauth";

  public static final String TYPE_BASIC = "basic";

  public static final String TYPE_OAUTH2 = "oauth2";

  public static Auth newNoAuth() {
    final Auth auth = new Auth();
    auth.setType(TYPE_NOAUTH);
    return auth;
  }

  private String type;

  private List<Basic> basic;

  private List<OAuth2> oauth2;
}

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

import java.util.Arrays;
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
public class Body {

  public static final String MODE_URLENCODED = "urlencoded";

  public static Body newUrlEncodedBody(UrlEncoded... urlEncoded) {
    final Body body = new Body();
    body.setMode(MODE_URLENCODED);
    if (urlEncoded != null && urlEncoded.length > 0) {
      body.setUrlencoded(Arrays.asList(urlEncoded));
    }
    return body;
  }

  private String mode;

  private List<UrlEncoded> urlencoded;

}

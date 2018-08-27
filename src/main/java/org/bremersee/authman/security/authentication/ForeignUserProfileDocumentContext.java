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

package org.bremersee.authman.security.authentication;

import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.Option;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import javax.validation.constraints.NotNull;
import lombok.EqualsAndHashCode;

/**
 * @author Christian Bremer
 */
@EqualsAndHashCode(of = "content")
public abstract class ForeignUserProfileDocumentContext implements ForeignUserProfile {

  private static final long serialVersionUID = 556686333391950461L;

  private byte[] content;

  private transient DocumentContext documentContext;

  public ForeignUserProfileDocumentContext(@NotNull final byte[] foreignUserProfileBytes) {
    this.content = foreignUserProfileBytes;
    createDocumentContext();
  }

  private void createDocumentContext() {
    if (content != null) {
      this.documentContext = JsonPath.parse(
          new ByteArrayInputStream(content),
          Configuration.builder().options(Option.SUPPRESS_EXCEPTIONS).build());
    }
  }

  @Override
  public String toString() {
    if (content == null) {
      return "ForeignUserProfileDocumentContext {content = null}";
    }
    return "ForeignUserProfileDocumentContext {" +
        "content = " + new String(content, StandardCharsets.UTF_8) +
        '}';
  }

  @SuppressWarnings("WeakerAccess")
  public DocumentContext getDocumentContext() {
    if (documentContext == null) {
      createDocumentContext();
    }
    return documentContext;
  }

  @SuppressWarnings("WeakerAccess")
  public <T> T read(String jsonPath, Class<T> cls) {
    final DocumentContext ctx = getDocumentContext();
    if (ctx == null) {
      return null;
    }
    return ctx.read(jsonPath, cls);
  }

}

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

package org.bremersee.authman.domain;

import java.io.Serializable;
import java.util.Date;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.domain.Persistable;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

/**
 * @author Christian Bremer
 */
@Data
@NoArgsConstructor
@Document(collection = "oauthApproval")
public class OAuth2Approval implements Serializable, Persistable<String> {

  private static final long serialVersionUID = -4763962214542746309L;

  @Id
  private String id;

  @Indexed
  private String userId;

  @Indexed
  private String clientId;

  @Indexed
  private String scope;

  private String status;

  @Indexed
  private Date expiresAt;

  private Date lastUpdatedAt;

  @Override
  public boolean isNew() {
    return id == null;
  }
}

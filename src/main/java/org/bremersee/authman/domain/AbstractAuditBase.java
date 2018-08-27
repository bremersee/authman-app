/*
 * Copyright 2016 the original author or authors.
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
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedBy;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.annotation.Version;
import org.springframework.data.domain.Persistable;
import org.springframework.data.mongodb.core.index.Indexed;

/**
 * @author Christian Bremer
 */
@Getter
@Setter
@EqualsAndHashCode(of = {"id", "version"})
@ToString
@NoArgsConstructor
public abstract class AbstractAuditBase implements Serializable, Persistable<String> {

  private static final long serialVersionUID = -4112778165408235916L;

  @Id
  private String id;

  @Version
  private Long version;

  @CreatedDate
  @Indexed(sparse = true)
  private Date created;

  @CreatedBy
  @Indexed(sparse = true)
  private String createdBy;

  @LastModifiedDate
  @Indexed(sparse = true)
  private Date modified;

  @LastModifiedBy
  @Indexed(sparse = true)
  private String modifiedBy;

  @Override
  public boolean isNew() {
    return getId() == null;
  }

}

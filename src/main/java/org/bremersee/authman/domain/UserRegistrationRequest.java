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

import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

/**
 * @author Christian Bremer
 */
@Getter
@Setter
@ToString(callSuper = true, exclude = {"password"})
@EqualsAndHashCode(callSuper = true)
@NoArgsConstructor
@Document(collection = "userRegistrationRequest")
public class UserRegistrationRequest extends AbstractAuditBase {

  @Indexed(unique = true)
  @Field("registrationHash")
  private String registrationHash;

  @Indexed
  @Field("registrationExpiration")
  private Date registrationExpiration;

  @Indexed
  @Field("userName")
  private String userName;

  @Field("password")
  private String password;

  @Field("displayName")
  private String displayName;

  @Field("preferredLocale")
  private String preferredLocale = Locale.getDefault().toString();

  @Field("preferredTimeZoneId")
  private String preferredTimeZoneId = TimeZone.getDefault().getID();

  @Field("email")
  private String email;

}

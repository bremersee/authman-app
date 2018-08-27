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

package org.bremersee.authman.security.core;

/**
 * @author Christian Bremer
 */
@SuppressWarnings({"unused", "WeakerAccess"})
public abstract class RoleConstants {

  public static final String ACTUATOR_ROLE = "ROLE_ACTUATOR";

  public static final String ADMIN_ROLE = "ROLE_ADMIN";

  public static final String SAMBA_ADMIN_ROLE = "ROLE_SAMBA_ADMIN";

  public static final String USER_ROLE = "ROLE_USER";

  public static final String DEVELOPER_ROLE = "ROLE_DEVELOPER";

  public static final String LOCAL_USER_ROLE = "ROLE_LOCAL_USER";

  public static final String LOCAL_MAIL_USER_ROLE = "ROLE_LOCAL_MAIL_USER";

  public static final String OAUTH2_CLIENT_ROLE = "ROLE_OAUTH2_CLIENT";

  public static String[] USER_ROLES = {
      ACTUATOR_ROLE,
      ADMIN_ROLE,
      USER_ROLE,
      DEVELOPER_ROLE,
      LOCAL_USER_ROLE,
      LOCAL_MAIL_USER_ROLE
  };

  public static String[] OAUTH2_CLIENT_ROLES = {
      OAUTH2_CLIENT_ROLE,
      ADMIN_ROLE,
      ACTUATOR_ROLE
  };

  private RoleConstants() {
  }

}

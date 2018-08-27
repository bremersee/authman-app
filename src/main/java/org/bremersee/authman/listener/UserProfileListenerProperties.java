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

package org.bremersee.authman.listener;

import feign.Logger.Level;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * @author Christian Bremer
 */
@ConfigurationProperties(prefix = "bremersee.user-listener")
@Getter
@Setter
@ToString
@EqualsAndHashCode
public class UserProfileListenerProperties implements Serializable {

  private static final long serialVersionUID = 8376334599360488710L;

  private List<UserProfileHttpListenerProperties> httpListeners = new ArrayList<>();

  @Getter
  @Setter
  @ToString(exclude = {"password"})
  @EqualsAndHashCode(exclude = {"password"})
  public static class UserProfileHttpListenerProperties implements Serializable {

    private static final long serialVersionUID = -4302184606179524950L;

    private boolean enabled = true;

    private String feignName;

    private String feignUrl;

    private Level feignLogLevel = Level.BASIC;

    private int connectTimeoutMillis = 10 * 1000;

    private int readTimeoutMillis = 60 * 1000;

    private long retryPeriod = 3000;

    private long retryMaxPeriod = 120000;

    private int retryMaxAttempts = 20;

    private String tokenEndpoint;

    private String clientId;

    private String username;

    private String password;

  }
}

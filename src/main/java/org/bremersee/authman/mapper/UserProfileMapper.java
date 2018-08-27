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

package org.bremersee.authman.mapper;

import javax.validation.constraints.NotNull;
import org.bremersee.authman.domain.UserProfile;
import org.bremersee.authman.model.UserProfileDto;

/**
 * @author Christian Bremer
 */
public interface UserProfileMapper {

  void mapToDto(@NotNull UserProfile source, @NotNull UserProfileDto destination);

  UserProfileDto mapToDto(@NotNull UserProfile source);

  void updateEntity(@NotNull UserProfileDto source, @NotNull UserProfile destination);

}

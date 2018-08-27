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

/**
 * This package contains change logs of mongobee (see {@link org.bremersee.authman.MongobeeConfiguration}).
 * <p>
 * A change log class looks like:
 * <pre>
 * {@literal @}ChangeLog
 * public class DatabaseChangelog {
 *
 *   {@literal @}ChangeSet(order = "001", id = "someChangeId", author = "testAuthor")
 *   public void importantWorkToDo(DB db){
 *      // task implementation
 *   }
 * }
 * </pre>
 *
 * @author Christian Bremer
 */
package org.bremersee.authman.domain.changelogs;
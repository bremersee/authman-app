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

package org.bremersee.authman.business;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.UUID;
import javax.mail.Message;
import javax.mail.internet.InternetAddress;
import javax.validation.constraints.NotNull;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.LocaleUtils;
import org.bremersee.authman.domain.UserProfileRepository;
import org.bremersee.authman.domain.UserRegistrationRequest;
import org.bremersee.authman.domain.UserRegistrationRequestRepository;
import org.bremersee.authman.exception.NotFoundException;
import org.bremersee.authman.listener.UserProfileListener;
import org.bremersee.authman.model.UserProfileCreateRequestDto;
import org.bremersee.authman.model.UserProfileDto;
import org.bremersee.authman.security.core.RoleConstants;
import org.bremersee.authman.security.core.SecurityHelper;
import org.bremersee.authman.security.crypto.password.PasswordEncoder;
import org.bremersee.authman.validation.ValidationProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessagePreparator;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * @author Christian Bremer
 */
@Component("registrationService")
@Slf4j
public class RegistrationServiceImpl extends AbstractUserProfileService
    implements RegistrationService, MessageSourceAware {

  private final RegistrationProperties registrationProperties;

  private final UserRegistrationRequestRepository registrationRepository;

  private final UserProfileService userService;

  private final UserProfileListener userProfileListener;

  private final PasswordEncoder passwordEncoder;

  private final JavaMailSender mailSender;

  @Autowired
  public RegistrationServiceImpl(
      final ValidationProperties validationProperties,
      final RegistrationProperties registrationProperties,
      final UserRegistrationRequestRepository registrationRepository,
      final UserProfileRepository userRepository,
      final UserProfileService userService,
      final UserProfileListener userProfileListener,
      final PasswordEncoder passwordEncoder,
      final JavaMailSender mailSender) {

    super(validationProperties, userRepository);
    this.registrationProperties = registrationProperties;
    this.registrationRepository = registrationRepository;
    this.userService = userService;
    this.userProfileListener = userProfileListener;
    this.passwordEncoder = passwordEncoder;
    this.mailSender = mailSender;
  }

  @Setter
  private MessageSource messageSource;

  private String buildRegistrationHash() {
    String hash = UUID.randomUUID().toString();
    while (registrationRepository.countByRegistrationHash(hash) > 0) {
      hash = UUID.randomUUID().toString();
    }
    return hash;
  }

  @Override
  public void saveRegistrationRequest(@NotNull final UserProfileCreateRequestDto request) {

    log.info("Saving registration request [{}].", request);

    validateUserProfileCreateRequest(request);

    UserRegistrationRequest entity = new UserRegistrationRequest();
    entity.setEmail(request.getEmail());
    entity.setDisplayName(request.getDisplayName());
    entity.setPassword(passwordEncoder.encode(request.getPassword()));
    entity.setPreferredLocale(request.getPreferredLocale());
    entity.setPreferredTimeZoneId(request.getPreferredTimeZoneId());
    entity.setRegistrationExpiration(registrationProperties.buildExpirationDate());
    entity.setRegistrationHash(buildRegistrationHash());
    entity.setUserName(request.getUserName());

    entity = registrationRepository.save(entity);

    sendRegistrationMail(entity);

    log.info("Registration successfully saved: {}", entity);

    userProfileListener.onUserRegistrationRequest(request, entity.getRegistrationExpiration());
  }

  @Override
  public UserProfileDto processUserRegistrationByHash(@NotNull String hash) {

    log.info("Processing user registration with hash [{}].");

    final UserRegistrationRequest request = registrationRepository
        .findByRegistrationHashAndRegistrationExpirationAfter(hash, new Date())
        .orElseThrow(NotFoundException::new);

    final UserProfileCreateRequestDto dto = new UserProfileCreateRequestDto();
    dto.setEmail(request.getEmail());
    dto.setDisplayName(request.getDisplayName());
    dto.setPassword(request.getPassword());
    dto.setPreferredLocale(request.getPreferredLocale());
    dto.setPreferredTimeZoneId(request.getPreferredTimeZoneId());
    dto.setUserName(request.getUserName());

    return SecurityHelper.runAs(
        "admin",
        new String[]{RoleConstants.ADMIN_ROLE},
        () -> userService.createUserProfile(dto, true, false));
  }

  private void sendRegistrationMail(final UserRegistrationRequest request) {

    MimeMessagePreparator preparator = mimeMessage -> {

      final String hash = URLEncoder
          .encode(request.getRegistrationHash(), StandardCharsets.UTF_8.name());
      final String href = registrationProperties.getLink().replace("{registrationHash}", hash);

      mimeMessage.setRecipient(Message.RecipientType.TO, new InternetAddress(request.getEmail()));
      mimeMessage.setFrom(new InternetAddress(registrationProperties.getSender()));
      mimeMessage.setSubject(getSubject(request));
      mimeMessage.setText("Dear " + request.getDisplayName()
          + ", welcome to bremersee.org! Please click " + href + " to complete your registration.");
    };

    this.mailSender.send(preparator);
  }

  private String getSubject(final UserRegistrationRequest request) {
    return messageSource.getMessage(
        registrationProperties.getSubjectCode(),
        new Object[0],
        "Welcome to bremersee.org",
        LocaleUtils.toLocale(request.getPreferredLocale()));
  }

  @Scheduled(cron = "0 13 0 * * ?") // second, minute, hour, day of month, month, day(s) of week
  @Override
  public void deleteExpired() {
    log.debug("Deleting expired user registration entries ...");
    final int size = registrationRepository.findExpiredAndRemove().size();
    log.debug("{} user registration entry/entries deleted.", size);
  }

}

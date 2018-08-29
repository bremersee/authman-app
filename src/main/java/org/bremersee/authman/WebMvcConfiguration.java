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

package org.bremersee.authman;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import lombok.extern.slf4j.Slf4j;
import org.bremersee.common.exhandling.ApiExceptionMapper;
import org.bremersee.common.exhandling.ApiExceptionMapperImpl;
import org.bremersee.common.exhandling.ApiExceptionResolver;
import org.bremersee.common.exhandling.ApiExceptionResolverProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.i18n.AcceptHeaderLocaleResolver;
import org.springframework.web.servlet.i18n.CookieLocaleResolver;
import org.springframework.web.servlet.i18n.SessionLocaleResolver;

/**
 * @author Christian Bremer
 */
@Configuration
@EnableConfigurationProperties({ApiExceptionResolverProperties.class})
@Slf4j
public class WebMvcConfiguration implements WebMvcConfigurer {

  private final ApiExceptionResolver apiExceptionResolver;

  @Autowired
  public WebMvcConfiguration(
      final Environment env,
      final ApiExceptionResolverProperties apiExceptionResolverProperties,
      final Jackson2ObjectMapperBuilder objectMapperBuilder) {

    final ApiExceptionMapper apiExceptionMapper = new ApiExceptionMapperImpl(
        apiExceptionResolverProperties,
        env.getProperty("spring.application.name"));

    this.apiExceptionResolver = new ApiExceptionResolver(
        apiExceptionResolverProperties,
        apiExceptionMapper);
    this.apiExceptionResolver.setObjectMapperBuilder(objectMapperBuilder);
  }

  @Bean
  public LocaleResolver localeResolver() {

    // TODO we need a resolver, that first looks for a cookie
    // if cookie == null -> reads accept header + create cookie
    // if cookie != null use locale

    SessionLocaleResolver slr = new SessionLocaleResolver();
    //slr.setDefaultLocale(Locale.getDefault());
    //slr.setDefaultTimeZone(TimeZone.getDefault());

    CookieLocaleResolver clr = new CookieLocaleResolver();
    //clr.setDefaultLocale(Locale.getDefault());
    //clr.setDefaultTimeZone(TimeZone.getDefault());

    List<Locale> supportedLocales = new ArrayList<>();
    supportedLocales.add(Locale.GERMANY);
    supportedLocales.add(Locale.UK);
    supportedLocales.add(Locale.US);
    AcceptHeaderLocaleResolver resolver = new AcceptHeaderLocaleResolver();
    resolver.setDefaultLocale(Locale.getDefault());
    resolver.setSupportedLocales(supportedLocales);
    return resolver;
  }

//        @Bean
//        public LocaleChangeInterceptor localeChangeInterceptor() {
//            LocaleChangeInterceptor lci = new LocaleChangeInterceptor();
//            lci.setParamName("lang");
//            return lci;
//        }

//        @Override
//        public void addInterceptors(InterceptorRegistry registry) {
//            registry.addInterceptor(localeChangeInterceptor());
//        }

  @Override
  public void addViewControllers(ViewControllerRegistry registry) {

    // Done by the login controller
    //registry.addViewController("/login").setViewName("login"); // NOSONAR

    // The confirm access view shows the requested scopes of a application/client and the user can
    // choose whether the application/client is allowed to access the data described by the scope
    // or not.
    //
    // If there's no view specified 'WhitelabelApprovalEndpoint' generates a default one.
    //
    // A simple customized view can be specified this way:
    //registry.addViewController("/oauth/confirm_access").setViewName("authorize"); // NOSONOR
    //
    // We provide the view by a controller ('AuthorizeController') which put further data to the
    // model.
    //
    // For more information to customize the authorization process see:
    // https://projects.spring.io/spring-security-oauth/docs/oauth2.html (Customizing the UI):
    //
    // An implementation of 'UserApprovalHandler' processes the selection of the scopes.
    // If there's an 'ApprovalStore' (like our), the implementation of 'UserApprovalHandler' will be
    // 'ApprovalStoreUserApprovalHandler'.
    // This handler can process each scope separately. In the confirm access view the scopes must
    // have an prefix (see OAuth2Utils#SCOPE_PREFIX) in the form, e. g.:
    // <input type="checkbox" name="scope.email.read" value="true" checked></input>
    //
    // All the authorization logic (it's the '/oauth/authorize' endpoint) in done by
    // 'AuthorizationEndpoint'.
  }

//  @Override
//  public void addResourceHandlers(ResourceHandlerRegistry registry) {
//    registry
//        .addResourceHandler("/webjars/**")
//        .addResourceLocations("classpath:/META-INF/resources/webjars/");
//  }

  @Override
  public void extendHandlerExceptionResolvers(List<HandlerExceptionResolver> exceptionResolvers) {
    exceptionResolvers.add(0, apiExceptionResolver);
  }

}

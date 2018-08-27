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

import org.bremersee.authman.security.authentication.ForeignUserProfileDefaultRequestor;
import org.bremersee.authman.security.authentication.ForeignUserProfileRequestor;
import org.bremersee.authman.security.authentication.OAuth2AuthenticationEntryPoint;
import org.bremersee.authman.security.authentication.OAuth2CallbackFilter;
import org.bremersee.authman.security.authentication.OAuth2MergeFilter;
import org.bremersee.authman.security.authentication.OAuth2RedirectFilter;
import org.bremersee.authman.security.authentication.facebook.FacebookAuthenticationProperties;
import org.bremersee.authman.security.authentication.facebook.FacebookUserProfileParser;
import org.bremersee.authman.security.authentication.github.GitHubAuthenticationProperties;
import org.bremersee.authman.security.authentication.github.GitHubUserProfileParser;
import org.bremersee.authman.security.authentication.google.GoogleAuthenticationProperties;
import org.bremersee.authman.security.authentication.google.GoogleUserProfileParser;
import org.bremersee.authman.security.core.RoleConstants;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;

/**
 * @author Christian Bremer
 */
@Configuration
@EnableConfigurationProperties({
    FacebookAuthenticationProperties.class,
    GitHubAuthenticationProperties.class,
    GoogleAuthenticationProperties.class
})
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

  private static final String LOGIN_PAGE = "/login";

  private FacebookAuthenticationProperties facebookAuthenticationProperties;

  private GitHubAuthenticationProperties gitHubAuthenticationProperties;

  private GoogleAuthenticationProperties googleAuthenticationProperties;

  private Jackson2ObjectMapperBuilder objectMapperBuilder;

  private RestTemplateBuilder restTemplateBuilder;

  public WebSecurityConfiguration(
      final FacebookAuthenticationProperties facebookAuthenticationProperties,
      final GitHubAuthenticationProperties gitHubAuthenticationProperties,
      final GoogleAuthenticationProperties googleAuthenticationProperties,
      final Jackson2ObjectMapperBuilder objectMapperBuilder,
      final RestTemplateBuilder restTemplateBuilder) {

    this.facebookAuthenticationProperties = facebookAuthenticationProperties;
    this.gitHubAuthenticationProperties = gitHubAuthenticationProperties;
    this.googleAuthenticationProperties = googleAuthenticationProperties;
    this.objectMapperBuilder = objectMapperBuilder;
    this.restTemplateBuilder = restTemplateBuilder;
  }

  @Bean("facebookEntryPoint")
  public OAuth2AuthenticationEntryPoint facebookEntryPoint() {
    return new OAuth2AuthenticationEntryPoint(facebookAuthenticationProperties);
  }

  @Bean("gitHubEntryPoint")
  public OAuth2AuthenticationEntryPoint gitHubEntryPoint() {
    return new OAuth2AuthenticationEntryPoint(gitHubAuthenticationProperties);
  }

  @Bean("googleEntryPoint")
  public OAuth2AuthenticationEntryPoint googleEntryPoint() {
    return new OAuth2AuthenticationEntryPoint(googleAuthenticationProperties);
  }

  @Bean("facebookRedirectFilter")
  public OAuth2RedirectFilter facebookRedirectFilter() {
    return new OAuth2RedirectFilter(facebookEntryPoint(),
        new AntPathRequestMatcher("/facebook/login", "POST"));
  }

  @Bean("gitHubRedirectFilter")
  public OAuth2RedirectFilter gitHubRedirectFilter() {
    return new OAuth2RedirectFilter(gitHubEntryPoint(),
        new AntPathRequestMatcher("/github/login", "POST"));
  }

  @Bean("googleRedirectFilter")
  public OAuth2RedirectFilter googleRedirectFilter() {
    return new OAuth2RedirectFilter(googleEntryPoint(),
        new AntPathRequestMatcher("/google/login", "POST"));
  }

  @Bean("facebookUserProfileParser")
  public FacebookUserProfileParser facebookUserProfileParser() {
    return new FacebookUserProfileParser(
        facebookAuthenticationProperties, objectMapperBuilder.build());
  }

  @Bean("facebookCallbackFilter")
  public OAuth2CallbackFilter facebookCallbackFilter()
      throws Exception {

    final AntPathRequestMatcher requestMatcher = new AntPathRequestMatcher(
        "/facebook/callback", "GET");
    final ForeignUserProfileRequestor userRequestor = new ForeignUserProfileDefaultRequestor(
        facebookAuthenticationProperties,
        new FacebookUserProfileParser(
            facebookAuthenticationProperties, objectMapperBuilder.build()))
        .restTemplateBuilder(restTemplateBuilder);
    final OAuth2CallbackFilter callbackFilter = new OAuth2CallbackFilter(
        facebookAuthenticationProperties, userRequestor, requestMatcher);
    callbackFilter.setAuthenticationManager(authenticationManagerBean());
    callbackFilter.setRestTemplateBuilder(restTemplateBuilder);
    return callbackFilter;
  }

  @Bean("gitHubUserProfileParser")
  public GitHubUserProfileParser gitHubUserProfileParser() {
    return new GitHubUserProfileParser(gitHubAuthenticationProperties);
  }

  @Bean("gitHubCallbackFilter")
  public OAuth2CallbackFilter gitHubCallbackFilter() throws Exception {

    final AntPathRequestMatcher requestMatcher = new AntPathRequestMatcher(
        "/github/callback", "GET");
    final ForeignUserProfileRequestor userRequestor = new ForeignUserProfileDefaultRequestor(
        gitHubAuthenticationProperties,
        new GitHubUserProfileParser(gitHubAuthenticationProperties))
        .restTemplateBuilder(restTemplateBuilder);
    final OAuth2CallbackFilter callbackFilter = new OAuth2CallbackFilter(
        gitHubAuthenticationProperties, userRequestor, requestMatcher);
    callbackFilter.setAuthenticationManager(authenticationManagerBean());
    callbackFilter.setRestTemplateBuilder(restTemplateBuilder);
    return callbackFilter;
  }

  @Bean("googleUserProfileParser")
  public GoogleUserProfileParser googleUserProfileParser() {
    return new GoogleUserProfileParser(googleAuthenticationProperties);
  }

  @Bean("googleCallbackFilter")
  public OAuth2CallbackFilter googleCallbackFilter() throws Exception {

    final AntPathRequestMatcher requestMatcher = new AntPathRequestMatcher(
        "/google/callback", "GET");
    final ForeignUserProfileRequestor userRequestor = new ForeignUserProfileDefaultRequestor(
        googleAuthenticationProperties,
        new GoogleUserProfileParser(googleAuthenticationProperties))
        .restTemplateBuilder(restTemplateBuilder);
    final OAuth2CallbackFilter callbackFilter = new OAuth2CallbackFilter(
        googleAuthenticationProperties, userRequestor, requestMatcher);
    callbackFilter.setAuthenticationManager(authenticationManagerBean());
    callbackFilter.setRestTemplateBuilder(restTemplateBuilder);
    return callbackFilter;
  }

  @Bean("oAuth2MergeFilter")
  public OAuth2MergeFilter oAuth2MergeFilter() throws Exception {
    OAuth2MergeFilter impl = new OAuth2MergeFilter();
    impl.setAuthenticationManager(authenticationManagerBean());
    return impl;
  }

  @Bean
  @Override
  public AuthenticationManager authenticationManagerBean() throws Exception {
    return super.authenticationManagerBean();
  }

  @Override
  public void configure(WebSecurity web) {
    web.ignoring().antMatchers(
        "/webjars/**",
        "/css/**",
        "/fonts/**",
        "/lib/**",
        "/oauth/uncache_approvals",
        "/oauth/cache_approvals");
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
        .addFilterBefore(facebookRedirectFilter(), X509AuthenticationFilter.class)
        .addFilterBefore(googleRedirectFilter(), X509AuthenticationFilter.class)
        .addFilterBefore(gitHubRedirectFilter(), X509AuthenticationFilter.class)
        .addFilterAfter(facebookCallbackFilter(), AbstractPreAuthenticatedProcessingFilter.class)
        .addFilterAfter(googleCallbackFilter(), AbstractPreAuthenticatedProcessingFilter.class)
        .addFilterAfter(gitHubCallbackFilter(), AbstractPreAuthenticatedProcessingFilter.class)
        .addFilterAfter(oAuth2MergeFilter(), AbstractPreAuthenticatedProcessingFilter.class)

        .requestMatcher(new NegatedRequestMatcher(
            new OrRequestMatcher(
                new AntPathRequestMatcher("/api/**"),
                new AntPathRequestMatcher("/actuator/**"))))

        .authorizeRequests()
        .antMatchers(HttpMethod.GET, "/merge*").permitAll()
        .antMatchers(HttpMethod.GET, "/register*").permitAll()
        .antMatchers(HttpMethod.POST, "/register*").permitAll()
        .antMatchers(HttpMethod.GET, "/password-reset*").permitAll()
        .antMatchers(HttpMethod.POST, "/password-reset*").permitAll()
        .antMatchers(HttpMethod.GET, "/logged-out*").permitAll()
        .anyRequest().hasAuthority(RoleConstants.USER_ROLE)

        .and()
        .formLogin().loginPage(LOGIN_PAGE).permitAll()

        .and()
        .logout().logoutSuccessUrl("/logged-out")

        .and()
        .rememberMe()
    ;
    //FilterComparator in HttpSecurity
  }

}

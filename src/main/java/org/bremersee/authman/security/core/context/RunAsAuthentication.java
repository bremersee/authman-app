package org.bremersee.authman.security.core.context;

import java.security.Principal;
import java.util.Collection;
import java.util.LinkedList;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * The authentication of a user that is put manually into the security context.
 *
 * @author Christian Bremer
 */
public class RunAsAuthentication implements Authentication {

  private static final long serialVersionUID = 1L;

  /**
   * The name of the run as authentication.
   */
  private final String name;

  /**
   * The roles (granted authorities) of the run as authority.
   */
  private final Collection<? extends GrantedAuthority> authorities;

  /**
   * Create an authority with the specified name and no roles (granted authorities).
   *
   * @param name the name
   */
  public RunAsAuthentication(final String name) {
    this.name = name;
    this.authorities = new LinkedList<>();
  }

  /**
   * Create an authority with the specified name and roles (granted authorities).
   *
   * @param name               the name
   * @param grantedAuthorities the roles (granted authorities)
   */
  public RunAsAuthentication(final String name, final String[] grantedAuthorities) {
    this.name = name;
    if (grantedAuthorities == null) {
      authorities = new LinkedList<>();
    } else {
      LinkedList<GrantedAuthority> list = new LinkedList<>();
      for (String ga : grantedAuthorities) {
        list.add(new SimpleGrantedAuthority(ga));
      }
      authorities = list;
    }
  }

  /**
   * Create an authority with the specified name and roles (granted authorities).
   *
   * @param name               the name
   * @param grantedAuthorities the roles (granted authorities)
   */
  public RunAsAuthentication(final String name,
      final Collection<? extends GrantedAuthority> grantedAuthorities) {
    this.name = name;
    this.authorities = grantedAuthorities == null ? new LinkedList<>() : grantedAuthorities;
  }

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return authorities;
  }

  @Override
  public Object getCredentials() {
    return null;
  }

  @Override
  public Object getDetails() {
    return null;
  }

  @Override
  public Object getPrincipal() {
    return new Principal() {
      @Override
      public String toString() {
        return getName();
      }

      @Override
      public String getName() {
        return name;
      }
    };
  }

  @Override
  public boolean isAuthenticated() {
    return true;
  }

  @Override
  public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException { // NOSONAR
  }

  @Override
  public String getName() {
    return name;
  }
}

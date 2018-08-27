package org.bremersee.authman.security.core.context;

/**
 * A run as callback implementation that returns nothing.
 *
 * @author Christian Bremer
 */
public abstract class RunAsCallbackWithoutResult implements RunAsCallback<Object>, Runnable {

  @Override
  public final Object execute() {
    run();
    return null;
  }

}

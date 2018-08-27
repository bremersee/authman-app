package org.bremersee.authman.security.core.context;

/**
 * The callback that will be executed by the run as utility.
 *
 * @author Christian Bremer
 */
public interface RunAsCallback<T> {

    /**
     * Executes the method and returns it's result.
     *
     * @return the result of the method
     */
    T execute();

}

package com.akmal.oauth2authorizationserver.shared.persistence;

import java.util.function.Supplier;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * A small helper class that propagates the transaction in case
 * we want to call a method within the same class for which Spring will not be able to proxy the call.
 */
@Component
public class TransactionPropagator {

  /**
   * Accepts a supplier function that is executed within the same transaction and returns the value of the execution.
   * If there is no active transaction, Spring will throw an exception and suspend the execution.
   *
   * @param supplier function that is executed within same transaction with a return value
   * @return the return value of the supplier function.
   * @param <T> type of the return value
   */
  @Transactional(propagation = Propagation.MANDATORY)
  public <T> T withinCurrent(Supplier<T> supplier) {
    return supplier.get();
  }

  /**
   * Accepts a runnable that is executed within the same transaction.
   * If there is no active transaction, Spring will throw an exception and suspend the execution.
   *
   * @param runnable function that is executed within same transaction/
   */
  @Transactional(propagation = Propagation.MANDATORY)
  public void withinCurrent(Runnable runnable) {
    runnable.run();
  }

  /**
   * Accepts a supplier function that is guaranteed to run in a new transaction.
   * If there exists a current transaction, then Spring will suspend it and create a new one.
   *
   * @param supplier that is executed within a new transaction and has a return value/
   * @return the return value of the supplier function.
   * @param <T> the return value's type.
   */
  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public <T> T withinNew(Supplier<T> supplier) {
    return supplier.get();
  }

  /**
   * Accepts a runnable that is guaranteed to run in a new transaction.
   * If there exists a current transaction, then Spring will suspend it and create a new one.
   *
   * @param runnable that is executed within a new transaction.
   */
  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public void withinNew(Runnable runnable) {
    runnable.run();
  }
}

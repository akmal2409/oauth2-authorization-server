package com.akmal.oauth2authorizationserver.validator;

/**
 * The interface defines a global contract for application wide validators.
 * @param <T> type of the entity to validate.
 */
public interface Validator<T> {

  boolean validate(T t);
}

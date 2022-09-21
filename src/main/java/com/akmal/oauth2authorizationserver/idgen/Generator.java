package com.akmal.oauth2authorizationserver.idgen;

public interface Generator<T> {

  T next();
}

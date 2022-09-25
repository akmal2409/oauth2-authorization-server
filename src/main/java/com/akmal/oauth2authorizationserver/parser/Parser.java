package com.akmal.oauth2authorizationserver.parser;

public interface Parser<IN, OUT> {

  OUT parse(IN value);
}
